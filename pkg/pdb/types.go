// Package pdb provides high-level access to Microsoft PDB debug files.
package pdb

// Function represents a function/procedure symbol.
type Function struct {
	Name          string `json:"name"`
	DemangledName string `json:"demangled_name,omitempty"`
	Offset        uint32 `json:"offset"`
	Segment       uint16 `json:"segment"`
	RVA           uint32 `json:"rva"`
	Length        uint32 `json:"length"`
	TypeIndex     uint32 `json:"type_index"`
	Signature     string `json:"signature"`
	IsGlobal      bool   `json:"is_global"`
	Module        string `json:"module,omitempty"`
}

// Variable represents a data/variable symbol.
type Variable struct {
	Name          string `json:"name"`
	DemangledName string `json:"demangled_name,omitempty"`
	Offset        uint32 `json:"offset"`
	Segment       uint16 `json:"segment"`
	RVA           uint32 `json:"rva"`
	TypeIndex     uint32 `json:"type_index"`
	TypeName      string `json:"type_name"`
	IsGlobal      bool   `json:"is_global"`
	Module        string `json:"module,omitempty"`
}

// TypeInfo represents a parsed type.
type TypeInfo struct {
	Index     uint32   `json:"index"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Size      uint64   `json:"size,omitempty"`
	Signature string   `json:"signature"`
	Members   []Member `json:"members,omitempty"`
}

// Member represents a struct/class/union member.
type Member struct {
	Name     string `json:"name"`
	TypeName string `json:"type_name"`
	Offset   uint64 `json:"offset"`
}

// PublicSymbol represents a public symbol from the public symbol stream.
type PublicSymbol struct {
	Name          string `json:"name"`
	DemangledName string `json:"demangled_name,omitempty"`
	Offset        uint32 `json:"offset"`
	Segment       uint16 `json:"segment"`
	RVA           uint32 `json:"rva"`
}

// SectionInfo represents a PE section.
type SectionInfo struct {
	Index  uint16 `json:"index"`            // 1-based section index
	Name   string `json:"name,omitempty"`   // Section name (e.g., ".text", ".data")
	Offset uint32 `json:"offset"`           // Virtual address (RVA base)
	Length uint32 `json:"length"`           // Section length in bytes
}

// ModuleInfo represents information about a compiled module.
type ModuleInfo struct {
	Name          string `json:"name"`
	ObjectFile    string `json:"object_file"`
	SymbolStream  uint16 `json:"symbol_stream"`
	SymbolSize    uint32 `json:"symbol_size"`
	SourceFiles   uint16 `json:"source_files"`
}

// PDBInfo contains basic PDB file information.
type PDBInfo struct {
	GUID      string            `json:"guid"`
	Age       uint32            `json:"age"`
	Version   uint32            `json:"version"`
	Machine   string            `json:"machine"`
	Streams   int               `json:"streams"`
	NamedStreams map[string]uint32 `json:"named_streams,omitempty"`
}
