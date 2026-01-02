// Package msf implements parsing for Microsoft's Multi-Stream Format (MSF) container.
package msf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// MSF 7.00 magic signature
var MSFMagic = []byte("Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00")

// SuperBlock is the header structure at the beginning of an MSF file.
// It contains metadata needed to navigate the file's stream structure.
type SuperBlock struct {
	Magic             [32]byte // Must be MSFMagic
	BlockSize         uint32   // Block size in bytes (512, 1024, 2048, or 4096)
	FreeBlockMapBlock uint32   // Index of active FPM block (1 or 2)
	NumBlocks         uint32   // Total number of blocks in file
	NumDirectoryBytes uint32   // Size of stream directory in bytes
	Unknown           uint32   // Reserved/unknown field
	BlockMapAddr      uint32   // Block index containing the stream directory block map
}

// SuperBlockSize is the size of the SuperBlock structure in bytes.
const SuperBlockSize = 56

// ValidBlockSizes are the allowed block sizes for MSF files.
var ValidBlockSizes = []uint32{512, 1024, 2048, 4096}

// ReadSuperBlock reads and validates the SuperBlock from the beginning of an MSF file.
func ReadSuperBlock(r io.Reader) (*SuperBlock, error) {
	var sb SuperBlock

	// Read magic
	if _, err := io.ReadFull(r, sb.Magic[:]); err != nil {
		return nil, fmt.Errorf("failed to read magic: %w", err)
	}

	// Validate magic
	if !bytes.Equal(sb.Magic[:], MSFMagic) {
		return nil, fmt.Errorf("invalid MSF magic: not a valid PDB file")
	}

	// Read remaining fields (little-endian)
	if err := binary.Read(r, binary.LittleEndian, &sb.BlockSize); err != nil {
		return nil, fmt.Errorf("failed to read BlockSize: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &sb.FreeBlockMapBlock); err != nil {
		return nil, fmt.Errorf("failed to read FreeBlockMapBlock: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &sb.NumBlocks); err != nil {
		return nil, fmt.Errorf("failed to read NumBlocks: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &sb.NumDirectoryBytes); err != nil {
		return nil, fmt.Errorf("failed to read NumDirectoryBytes: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &sb.Unknown); err != nil {
		return nil, fmt.Errorf("failed to read Unknown: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &sb.BlockMapAddr); err != nil {
		return nil, fmt.Errorf("failed to read BlockMapAddr: %w", err)
	}

	// Validate block size
	if !isValidBlockSize(sb.BlockSize) {
		return nil, fmt.Errorf("invalid block size: %d", sb.BlockSize)
	}

	// Validate FreeBlockMapBlock
	if sb.FreeBlockMapBlock != 1 && sb.FreeBlockMapBlock != 2 {
		return nil, fmt.Errorf("invalid FreeBlockMapBlock: %d (must be 1 or 2)", sb.FreeBlockMapBlock)
	}

	return &sb, nil
}

// NumDirectoryBlocks returns the number of blocks needed to store the stream directory.
func (sb *SuperBlock) NumDirectoryBlocks() uint32 {
	return (sb.NumDirectoryBytes + sb.BlockSize - 1) / sb.BlockSize
}

// FileSize returns the expected file size based on block count.
func (sb *SuperBlock) FileSize() int64 {
	return int64(sb.NumBlocks) * int64(sb.BlockSize)
}

func isValidBlockSize(size uint32) bool {
	for _, valid := range ValidBlockSizes {
		if size == valid {
			return true
		}
	}
	return false
}
