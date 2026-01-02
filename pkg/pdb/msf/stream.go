package msf

import (
	"io"
)

// Stream represents a single stream within an MSF file.
// Streams are composed of potentially non-contiguous blocks.
type Stream struct {
	msf    *MSF
	size   uint32
	blocks []uint32
}

// Size returns the size of the stream in bytes.
func (s *Stream) Size() uint32 {
	return s.size
}

// Blocks returns the block indices that make up this stream.
func (s *Stream) Blocks() []uint32 {
	return s.blocks
}

// StreamReader provides sequential read access to a stream's data,
// handling the non-contiguous block layout transparently.
type StreamReader struct {
	stream      *Stream
	offset      int64 // Current position in the stream
	blockOffset int   // Current block index within stream.blocks
	posInBlock  int   // Position within current block
}

// NewStreamReader creates a new reader for the given stream.
func NewStreamReader(s *Stream) *StreamReader {
	return &StreamReader{
		stream:      s,
		offset:      0,
		blockOffset: 0,
		posInBlock:  0,
	}
}

// Read implements io.Reader for streaming data from non-contiguous blocks.
func (sr *StreamReader) Read(p []byte) (int, error) {
	if sr.offset >= int64(sr.stream.size) {
		return 0, io.EOF
	}

	totalRead := 0
	blockSize := int(sr.stream.msf.superBlock.BlockSize)

	for len(p) > 0 && sr.offset < int64(sr.stream.size) {
		// Determine how many bytes we can read from the current block
		remainingInBlock := blockSize - sr.posInBlock
		remainingInStream := int64(sr.stream.size) - sr.offset
		toRead := len(p)

		if toRead > remainingInBlock {
			toRead = remainingInBlock
		}
		if int64(toRead) > remainingInStream {
			toRead = int(remainingInStream)
		}

		// Read from the current block
		blockIndex := sr.stream.blocks[sr.blockOffset]
		fileOffset := int64(blockIndex)*int64(blockSize) + int64(sr.posInBlock)

		n, err := sr.stream.msf.readAt(p[:toRead], fileOffset)
		if err != nil && err != io.EOF {
			return totalRead, err
		}

		totalRead += n
		sr.offset += int64(n)
		sr.posInBlock += n
		p = p[n:]

		// Move to next block if we've exhausted this one
		if sr.posInBlock >= blockSize {
			sr.blockOffset++
			sr.posInBlock = 0
		}
	}

	return totalRead, nil
}

// Seek implements io.Seeker.
func (sr *StreamReader) Seek(offset int64, whence int) (int64, error) {
	var newOffset int64
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = sr.offset + offset
	case io.SeekEnd:
		newOffset = int64(sr.stream.size) + offset
	}

	if newOffset < 0 {
		newOffset = 0
	}
	if newOffset > int64(sr.stream.size) {
		newOffset = int64(sr.stream.size)
	}

	sr.offset = newOffset
	blockSize := int64(sr.stream.msf.superBlock.BlockSize)
	sr.blockOffset = int(newOffset / blockSize)
	sr.posInBlock = int(newOffset % blockSize)

	return sr.offset, nil
}

// ReadAll reads the entire stream contents into a byte slice.
func (s *Stream) ReadAll() ([]byte, error) {
	data := make([]byte, s.size)
	reader := NewStreamReader(s)
	_, err := io.ReadFull(reader, data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// StreamDirectory represents the directory of all streams in the MSF file.
type StreamDirectory struct {
	NumStreams   uint32
	StreamSizes  []uint32
	StreamBlocks [][]uint32
}
