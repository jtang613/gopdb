package msf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// MSF represents an opened MSF (Multi-Stream Format) file.
type MSF struct {
	file       *os.File
	superBlock *SuperBlock
	directory  *StreamDirectory
	streams    []*Stream
}

// Open opens an MSF file and parses its structure.
func Open(path string) (*MSF, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	msf := &MSF{file: f}

	// Read SuperBlock
	msf.superBlock, err = ReadSuperBlock(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to read superblock: %w", err)
	}

	// Read stream directory
	if err := msf.readStreamDirectory(); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to read stream directory: %w", err)
	}

	// Build stream objects
	msf.buildStreams()

	return msf, nil
}

// Close closes the MSF file.
func (m *MSF) Close() error {
	if m.file != nil {
		return m.file.Close()
	}
	return nil
}

// SuperBlock returns the MSF SuperBlock.
func (m *MSF) SuperBlock() *SuperBlock {
	return m.superBlock
}

// NumStreams returns the number of streams in the file.
func (m *MSF) NumStreams() int {
	return int(m.directory.NumStreams)
}

// Stream returns the stream at the given index.
func (m *MSF) Stream(index int) (*Stream, error) {
	if index < 0 || index >= len(m.streams) {
		return nil, fmt.Errorf("stream index %d out of range [0, %d)", index, len(m.streams))
	}
	return m.streams[index], nil
}

// StreamReader returns a reader for the stream at the given index.
func (m *MSF) StreamReader(index int) (*StreamReader, error) {
	s, err := m.Stream(index)
	if err != nil {
		return nil, err
	}
	return NewStreamReader(s), nil
}

// readAt reads data from the file at the given offset.
func (m *MSF) readAt(p []byte, off int64) (int, error) {
	return m.file.ReadAt(p, off)
}

// readStreamDirectory reads and parses the stream directory.
func (m *MSF) readStreamDirectory() error {
	blockSize := m.superBlock.BlockSize

	// Read the block map (list of blocks containing the stream directory)
	blockMapOffset := int64(m.superBlock.BlockMapAddr) * int64(blockSize)
	numDirBlocks := m.superBlock.NumDirectoryBlocks()

	// Read block map entries
	blockMap := make([]uint32, numDirBlocks)
	if _, err := m.file.Seek(blockMapOffset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to block map: %w", err)
	}
	if err := binary.Read(m.file, binary.LittleEndian, blockMap); err != nil {
		return fmt.Errorf("failed to read block map: %w", err)
	}

	// Read the stream directory data from the block map blocks
	dirData := make([]byte, m.superBlock.NumDirectoryBytes)
	bytesRead := 0
	for _, blockIdx := range blockMap {
		offset := int64(blockIdx) * int64(blockSize)
		toRead := int(blockSize)
		if bytesRead+toRead > len(dirData) {
			toRead = len(dirData) - bytesRead
		}
		if _, err := m.file.ReadAt(dirData[bytesRead:bytesRead+toRead], offset); err != nil {
			return fmt.Errorf("failed to read directory block %d: %w", blockIdx, err)
		}
		bytesRead += toRead
	}

	// Parse the stream directory
	return m.parseStreamDirectory(dirData)
}

// parseStreamDirectory parses the stream directory from raw bytes.
func (m *MSF) parseStreamDirectory(data []byte) error {
	r := bytes.NewReader(data)

	var numStreams uint32
	if err := binary.Read(r, binary.LittleEndian, &numStreams); err != nil {
		return fmt.Errorf("failed to read NumStreams: %w", err)
	}

	// Read stream sizes
	streamSizes := make([]uint32, numStreams)
	for i := uint32(0); i < numStreams; i++ {
		if err := binary.Read(r, binary.LittleEndian, &streamSizes[i]); err != nil {
			return fmt.Errorf("failed to read stream size %d: %w", i, err)
		}
	}

	// Read stream block lists
	blockSize := m.superBlock.BlockSize
	streamBlocks := make([][]uint32, numStreams)
	for i := uint32(0); i < numStreams; i++ {
		size := streamSizes[i]
		// Size of 0xFFFFFFFF indicates an unused/deleted stream
		if size == 0xFFFFFFFF {
			streamBlocks[i] = nil
			continue
		}
		numBlocks := (size + blockSize - 1) / blockSize
		blocks := make([]uint32, numBlocks)
		for j := uint32(0); j < numBlocks; j++ {
			if err := binary.Read(r, binary.LittleEndian, &blocks[j]); err != nil {
				return fmt.Errorf("failed to read block index for stream %d: %w", i, err)
			}
		}
		streamBlocks[i] = blocks
	}

	m.directory = &StreamDirectory{
		NumStreams:   numStreams,
		StreamSizes:  streamSizes,
		StreamBlocks: streamBlocks,
	}

	return nil
}

// buildStreams creates Stream objects for all streams in the directory.
func (m *MSF) buildStreams() {
	m.streams = make([]*Stream, m.directory.NumStreams)
	for i := uint32(0); i < m.directory.NumStreams; i++ {
		size := m.directory.StreamSizes[i]
		if size == 0xFFFFFFFF {
			// Unused stream
			m.streams[i] = &Stream{
				msf:    m,
				size:   0,
				blocks: nil,
			}
		} else {
			m.streams[i] = &Stream{
				msf:    m,
				size:   size,
				blocks: m.directory.StreamBlocks[i],
			}
		}
	}
}

// BlockSize returns the block size used by this MSF file.
func (m *MSF) BlockSize() uint32 {
	return m.superBlock.BlockSize
}
