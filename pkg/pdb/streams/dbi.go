package streams

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// DBI Stream versions
const (
	DBIStreamVersionVC41   = 930803
	DBIStreamVersionV50    = 19960307
	DBIStreamVersionV60    = 19970606
	DBIStreamVersionV70    = 19990903
	DBIStreamVersionV110   = 20091201
)

// Machine types
const (
	MachineUnknown   = 0x0000
	MachineI386      = 0x014c
	MachineIA64      = 0x0200
	MachineAMD64     = 0x8664
	MachineARM       = 0x01c0
	MachineARM64     = 0xAA64
)

// DBIHeader is the fixed header of the DBI stream (64 bytes).
type DBIHeader struct {
	VersionSignature       int32  // Always -1
	VersionHeader          uint32 // DBI version
	Age                    uint32 // PDB age
	GlobalStreamIndex      uint16 // Global symbols stream index
	BuildNumber            uint16 // Toolchain version
	PublicStreamIndex      uint16 // Public symbols stream index
	PdbDllVersion          uint16
	SymRecordStream        uint16 // Symbol record stream index
	PdbDllRbld             uint16
	ModInfoSize            int32  // Size of module info substream
	SectionContributionSize int32 // Size of section contribution substream
	SectionMapSize         int32  // Size of section map substream
	SourceInfoSize         int32  // Size of source info substream
	TypeServerMapSize      int32  // Size of type server map substream
	MFCTypeServerIndex     uint32
	OptionalDbgHeaderSize  int32  // Size of optional debug header
	ECSubstreamSize        int32  // Size of EC substream
	Flags                  uint16
	Machine                uint16 // CPU type
	Padding                uint32
}

// DBIStream represents the parsed DBI stream.
type DBIStream struct {
	Header          DBIHeader
	Modules         []ModuleInfo
	SectionContribs []SectionContrib
}

// ModuleInfo contains information about a compiled module.
type ModuleInfo struct {
	Unused1           uint32
	SectionContrib    SectionContrib
	Flags             uint16
	ModuleSymStream   uint16 // Stream containing module symbols (-1 if none)
	SymByteSize       uint32 // Size of symbol data in bytes
	C11ByteSize       uint32 // Size of C11 line info
	C13ByteSize       uint32 // Size of C13 line info
	SourceFileCount   uint16
	Padding           uint16
	Unused2           uint32
	SourceFileNameIndex uint32
	PdbFilePathNameIndex uint32
	ModuleName        string // Object file name
	ObjFileName       string // Archive or object file path
}

// SectionContrib describes a section contribution from a module.
type SectionContrib struct {
	Section         uint16
	Padding1        uint16
	Offset          int32
	Size            int32
	Characteristics uint32
	ModuleIndex     uint16
	Padding2        uint16
	DataCrc         uint32
	RelocCrc        uint32
}

// ReadDBIStream parses the DBI stream.
func ReadDBIStream(data []byte) (*DBIStream, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("DBI stream too small: %d bytes", len(data))
	}

	r := bytes.NewReader(data)

	var header DBIHeader
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read DBI header: %w", err)
	}

	// Validate header
	if header.VersionSignature != -1 {
		return nil, fmt.Errorf("invalid DBI version signature: %d", header.VersionSignature)
	}

	dbi := &DBIStream{
		Header: header,
	}

	// Calculate substream offsets
	modInfoOffset := 64
	secContribOffset := modInfoOffset + int(header.ModInfoSize)
	// secMapOffset := secContribOffset + int(header.SectionContributionSize)
	// sourceInfoOffset := secMapOffset + int(header.SectionMapSize)

	// Parse module info substream
	if header.ModInfoSize > 0 {
		modInfoEnd := modInfoOffset + int(header.ModInfoSize)
		if modInfoEnd <= len(data) {
			modules, err := parseModuleInfo(data[modInfoOffset:modInfoEnd])
			if err != nil {
				return nil, fmt.Errorf("failed to parse module info: %w", err)
			}
			dbi.Modules = modules
		}
	}

	// Parse section contributions
	if header.SectionContributionSize > 0 {
		secContribEnd := secContribOffset + int(header.SectionContributionSize)
		if secContribEnd <= len(data) {
			contribs, err := parseSectionContribs(data[secContribOffset:secContribEnd])
			if err != nil {
				return nil, fmt.Errorf("failed to parse section contributions: %w", err)
			}
			dbi.SectionContribs = contribs
		}
	}

	return dbi, nil
}

// parseModuleInfo parses the module info substream.
func parseModuleInfo(data []byte) ([]ModuleInfo, error) {
	var modules []ModuleInfo
	offset := 0

	for offset < len(data) {
		if offset+64 > len(data) {
			break
		}

		var mod ModuleInfo

		// Read fixed fields
		mod.Unused1 = binary.LittleEndian.Uint32(data[offset:])
		offset += 4

		// SectionContrib (28 bytes)
		mod.SectionContrib.Section = binary.LittleEndian.Uint16(data[offset:])
		offset += 2
		mod.SectionContrib.Padding1 = binary.LittleEndian.Uint16(data[offset:])
		offset += 2
		mod.SectionContrib.Offset = int32(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
		mod.SectionContrib.Size = int32(binary.LittleEndian.Uint32(data[offset:]))
		offset += 4
		mod.SectionContrib.Characteristics = binary.LittleEndian.Uint32(data[offset:])
		offset += 4
		mod.SectionContrib.ModuleIndex = binary.LittleEndian.Uint16(data[offset:])
		offset += 2
		mod.SectionContrib.Padding2 = binary.LittleEndian.Uint16(data[offset:])
		offset += 2
		mod.SectionContrib.DataCrc = binary.LittleEndian.Uint32(data[offset:])
		offset += 4
		mod.SectionContrib.RelocCrc = binary.LittleEndian.Uint32(data[offset:])
		offset += 4

		mod.Flags = binary.LittleEndian.Uint16(data[offset:])
		offset += 2
		mod.ModuleSymStream = binary.LittleEndian.Uint16(data[offset:])
		offset += 2
		mod.SymByteSize = binary.LittleEndian.Uint32(data[offset:])
		offset += 4
		mod.C11ByteSize = binary.LittleEndian.Uint32(data[offset:])
		offset += 4
		mod.C13ByteSize = binary.LittleEndian.Uint32(data[offset:])
		offset += 4
		mod.SourceFileCount = binary.LittleEndian.Uint16(data[offset:])
		offset += 2
		mod.Padding = binary.LittleEndian.Uint16(data[offset:])
		offset += 2
		mod.Unused2 = binary.LittleEndian.Uint32(data[offset:])
		offset += 4
		mod.SourceFileNameIndex = binary.LittleEndian.Uint32(data[offset:])
		offset += 4
		mod.PdbFilePathNameIndex = binary.LittleEndian.Uint32(data[offset:])
		offset += 4

		// Read null-terminated module name
		if offset >= len(data) {
			break
		}
		modNameEnd := bytes.IndexByte(data[offset:], 0)
		if modNameEnd == -1 {
			break
		}
		mod.ModuleName = string(data[offset : offset+modNameEnd])
		offset += modNameEnd + 1

		// Read null-terminated object file name
		if offset >= len(data) {
			break
		}
		objNameEnd := bytes.IndexByte(data[offset:], 0)
		if objNameEnd == -1 {
			break
		}
		mod.ObjFileName = string(data[offset : offset+objNameEnd])
		offset += objNameEnd + 1

		// Align to 4-byte boundary
		offset = (offset + 3) & ^3

		modules = append(modules, mod)
	}

	return modules, nil
}

// parseSectionContribs parses the section contribution substream.
func parseSectionContribs(data []byte) ([]SectionContrib, error) {
	if len(data) < 4 {
		return nil, nil
	}

	r := bytes.NewReader(data)

	// Read version
	var version uint32
	if err := binary.Read(r, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("failed to read section contrib version: %w", err)
	}

	// Determine entry size based on version
	entrySize := 28 // Ver60 size
	if version == 0xeffe0000+20140516 {
		entrySize = 32 // V2 adds ISectCoff
	}

	remaining := len(data) - 4
	numEntries := remaining / entrySize

	var contribs []SectionContrib
	for i := 0; i < numEntries; i++ {
		var contrib SectionContrib
		if err := binary.Read(r, binary.LittleEndian, &contrib.Section); err != nil {
			break
		}
		if err := binary.Read(r, binary.LittleEndian, &contrib.Padding1); err != nil {
			break
		}
		if err := binary.Read(r, binary.LittleEndian, &contrib.Offset); err != nil {
			break
		}
		if err := binary.Read(r, binary.LittleEndian, &contrib.Size); err != nil {
			break
		}
		if err := binary.Read(r, binary.LittleEndian, &contrib.Characteristics); err != nil {
			break
		}
		if err := binary.Read(r, binary.LittleEndian, &contrib.ModuleIndex); err != nil {
			break
		}
		if err := binary.Read(r, binary.LittleEndian, &contrib.Padding2); err != nil {
			break
		}
		if err := binary.Read(r, binary.LittleEndian, &contrib.DataCrc); err != nil {
			break
		}
		if err := binary.Read(r, binary.LittleEndian, &contrib.RelocCrc); err != nil {
			break
		}

		// Skip extra field in V2
		if entrySize == 32 {
			var dummy uint32
			binary.Read(r, binary.LittleEndian, &dummy)
		}

		contribs = append(contribs, contrib)
	}

	return contribs, nil
}

// MachineTypeName returns the human-readable name for a machine type.
func MachineTypeName(machine uint16) string {
	switch machine {
	case MachineI386:
		return "x86"
	case MachineAMD64:
		return "x64"
	case MachineARM:
		return "ARM"
	case MachineARM64:
		return "ARM64"
	case MachineIA64:
		return "IA64"
	default:
		return fmt.Sprintf("0x%04x", machine)
	}
}

// HasSymbols returns true if the module has symbol information.
func (m *ModuleInfo) HasSymbols() bool {
	return m.ModuleSymStream != 0xFFFF && m.SymByteSize > 0
}
