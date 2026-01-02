// Package codeview provides parsing for CodeView debug symbol records.
package codeview

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Symbol type constants (S_* values)
const (
	S_COMPILE       = 0x0001
	S_REGISTER      = 0x0002
	S_CONSTANT      = 0x0003
	S_UDT           = 0x0004
	S_SSEARCH       = 0x0005
	S_END           = 0x0006
	S_SKIP          = 0x0007
	S_CVRESERVE     = 0x0008
	S_OBJNAME       = 0x0009
	S_ENDARG        = 0x000a
	S_COBOLUDT      = 0x000b
	S_MANYREG       = 0x000c
	S_RETURN        = 0x000d
	S_ENTRYTHIS     = 0x000e

	S_BPREL16       = 0x0100
	S_LDATA16       = 0x0101
	S_GDATA16       = 0x0102
	S_PUB16         = 0x0103
	S_LPROC16       = 0x0104
	S_GPROC16       = 0x0105
	S_THUNK16       = 0x0106
	S_BLOCK16       = 0x0107
	S_WITH16        = 0x0108
	S_LABEL16       = 0x0109
	S_CEXMODEL16    = 0x010a
	S_VFTABLE16     = 0x010b
	S_REGREL16      = 0x010c

	S_BPREL32_16t   = 0x0200
	S_LDATA32_16t   = 0x0201
	S_GDATA32_16t   = 0x0202
	S_PUB32_16t     = 0x0203
	S_LPROC32_16t   = 0x0204
	S_GPROC32_16t   = 0x0205
	S_THUNK32       = 0x0206
	S_BLOCK32       = 0x0207
	S_WITH32        = 0x0208
	S_LABEL32       = 0x0209
	S_CEXMODEL32    = 0x020a
	S_VFTABLE32_16t = 0x020b
	S_REGREL32_16t  = 0x020c
	S_LTHREAD32_16t = 0x020d
	S_GTHREAD32_16t = 0x020e

	S_SLINK32       = 0x0230

	S_LPROCMIPS_16t = 0x0300
	S_GPROCMIPS_16t = 0x0301

	S_PROCREF       = 0x0400
	S_DATAREF       = 0x0401
	S_ALIGN         = 0x0402
	S_LPROCREF      = 0x0403

	S_OEM           = 0x0404

	// 32-bit symbol types
	S_TI16_MAX      = 0x1000

	S_REGISTER_ST   = 0x1001
	S_CONSTANT_ST   = 0x1002
	S_UDT_ST        = 0x1003
	S_COBOLUDT_ST   = 0x1004
	S_MANYREG_ST    = 0x1005
	S_BPREL32_ST    = 0x1006
	S_LDATA32_ST    = 0x1007
	S_GDATA32_ST    = 0x1008
	S_PUB32_ST      = 0x1009
	S_LPROC32_ST    = 0x100a
	S_GPROC32_ST    = 0x100b
	S_VFTABLE32     = 0x100c
	S_REGREL32_ST   = 0x100d
	S_LTHREAD32_ST  = 0x100e
	S_GTHREAD32_ST  = 0x100f
	S_LPROCMIPS_ST  = 0x1010
	S_GPROCMIPS_ST  = 0x1011

	S_FRAMEPROC     = 0x1012
	S_COMPILE2_ST   = 0x1013

	S_MANYREG2_ST   = 0x1014
	S_LPROCIA64_ST  = 0x1015
	S_GPROCIA64_ST  = 0x1016

	S_LOCALSLOT_ST  = 0x1017
	S_PARAMSLOT_ST  = 0x1018

	S_ANNOTATION    = 0x1019

	S_GMANPROC_ST   = 0x101a
	S_LMANPROC_ST   = 0x101b
	S_RESERVED1     = 0x101c
	S_RESERVED2     = 0x101d
	S_RESERVED3     = 0x101e
	S_RESERVED4     = 0x101f

	S_LMANDATA_ST   = 0x1020
	S_GMANDATA_ST   = 0x1021
	S_MANFRAMEREL_ST = 0x1022
	S_MANREGISTER_ST = 0x1023
	S_MANSLOT_ST    = 0x1024
	S_MANMANYREG_ST = 0x1025
	S_MANREGREL_ST  = 0x1026
	S_MANMANYREG2_ST = 0x1027
	S_MANTYPREF     = 0x1028

	S_UNAMESPACE_ST = 0x1029

	// Symbols without the _ST suffix (new format with null-terminated strings)
	S_ST_MAX        = 0x1100

	S_OBJNAME_ST    = 0x1101
	S_THUNK32_ST    = 0x1102
	S_BLOCK32_ST    = 0x1103
	S_WITH32_ST     = 0x1104
	S_LABEL32_ST    = 0x1105

	S_REGISTER_NEW  = 0x1106
	S_CONSTANT_NEW  = 0x1107
	S_UDT_NEW       = 0x1108
	S_COBOLUDT_NEW  = 0x1109
	S_MANYREG_NEW   = 0x110a
	S_BPREL32_NEW   = 0x110b
	S_LDATA32       = 0x110c
	S_GDATA32       = 0x110d
	S_PUB32         = 0x110e
	S_LPROC32       = 0x110f
	S_GPROC32       = 0x1110
	S_REGREL32      = 0x1111
	S_LTHREAD32     = 0x1112
	S_GTHREAD32     = 0x1113
	S_LPROCMIPS     = 0x1114
	S_GPROCMIPS     = 0x1115
	S_COMPILE2      = 0x1116
	S_MANYREG2      = 0x1117
	S_LPROCIA64     = 0x1118
	S_GPROCIA64     = 0x1119
	S_LOCALSLOT     = 0x111a
	S_SLOT          = 0x111a
	S_PARAMSLOT     = 0x111b

	S_LMANDATA      = 0x111c
	S_GMANDATA      = 0x111d
	S_MANFRAMEREL   = 0x111e
	S_MANREGISTER   = 0x111f
	S_MANSLOT       = 0x1120
	S_MANMANYREG    = 0x1121
	S_MANREGREL     = 0x1122
	S_MANMANYREG2   = 0x1123

	S_UNAMESPACE    = 0x1124

	S_PROCREF_NEW   = 0x1125
	S_DATAREF_NEW   = 0x1126
	S_LPROCREF_NEW  = 0x1127
	S_ANNOTATIONREF = 0x1128
	S_TOKENREF      = 0x1129

	S_GMANPROC      = 0x112a
	S_LMANPROC      = 0x112b

	S_TRAMPOLINE    = 0x112c
	S_MANCONSTANT   = 0x112d

	S_ATTR_FRAMEREL  = 0x112e
	S_ATTR_REGISTER  = 0x112f
	S_ATTR_REGREL    = 0x1130
	S_ATTR_MANYREG   = 0x1131

	S_SEPCODE       = 0x1132
	S_LOCAL_2005    = 0x1133
	S_DEFRANGE_2005 = 0x1134
	S_DEFRANGE2_2005 = 0x1135

	S_SECTION       = 0x1136
	S_COFFGROUP     = 0x1137
	S_EXPORT        = 0x1138

	S_CALLSITEINFO  = 0x1139
	S_FRAMECOOKIE   = 0x113a

	S_DISCARDED     = 0x113b

	S_COMPILE3      = 0x113c
	S_ENVBLOCK      = 0x113d

	S_LOCAL         = 0x113e
	S_DEFRANGE      = 0x113f
	S_DEFRANGE_SUBFIELD = 0x1140
	S_DEFRANGE_REGISTER = 0x1141
	S_DEFRANGE_FRAMEPOINTER_REL = 0x1142
	S_DEFRANGE_SUBFIELD_REGISTER = 0x1143
	S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE = 0x1144
	S_DEFRANGE_REGISTER_REL = 0x1145

	S_LPROC32_ID    = 0x1146
	S_GPROC32_ID    = 0x1147
	S_LPROCMIPS_ID  = 0x1148
	S_GPROCMIPS_ID  = 0x1149
	S_LPROCIA64_ID  = 0x114a
	S_GPROCIA64_ID  = 0x114b

	S_BUILDINFO     = 0x114c
	S_INLINESITE    = 0x114d
	S_INLINESITE_END = 0x114e
	S_PROC_ID_END   = 0x114f

	S_DEFRANGE_HLSL = 0x1150
	S_GDATA_HLSL    = 0x1151
	S_LDATA_HLSL    = 0x1152

	S_FILESTATIC    = 0x1153

	S_LOCAL_DPC_GROUPSHARED = 0x1154
	S_LPROC32_DPC   = 0x1155
	S_LPROC32_DPC_ID = 0x1156
	S_DEFRANGE_DPC_PTR_TAG = 0x1157
	S_DPC_SYM_TAG_MAP = 0x1158

	S_ARMSWITCHTABLE = 0x1159
	S_CALLEES       = 0x115a
	S_CALLERS       = 0x115b
	S_POGODATA      = 0x115c
	S_INLINESITE2   = 0x115d

	S_HEAPALLOCSITE = 0x115e

	S_MOD_TYPEREF   = 0x115f
	S_REF_MINIPDB   = 0x1160
	S_PDBMAP        = 0x1161

	S_GDATA_HLSL32  = 0x1162
	S_LDATA_HLSL32  = 0x1163
	S_GDATA_HLSL32_EX = 0x1164
	S_LDATA_HLSL32_EX = 0x1165

	S_FASTLINK      = 0x1167
	S_INLINEES      = 0x1168
)

// SymbolRecord represents a parsed CodeView symbol record.
type SymbolRecord struct {
	Kind uint16
	Data []byte
}

// ProcSym represents a procedure/function symbol (S_GPROC32, S_LPROC32, etc.)
type ProcSym struct {
	Parent       uint32 // Pointer to parent
	End          uint32 // Pointer to end
	Next         uint32 // Pointer to next symbol
	Length       uint32 // Procedure length
	DbgStart     uint32 // Debug start offset
	DbgEnd       uint32 // Debug end offset
	TypeIndex    uint32 // Type index
	Offset       uint32 // Code offset
	Segment      uint16 // Code segment
	Flags        uint8  // Procedure flags
	Name         string // Procedure name
}

// DataSym represents a data/variable symbol (S_GDATA32, S_LDATA32, etc.)
type DataSym struct {
	TypeIndex uint32 // Type index
	Offset    uint32 // Data offset
	Segment   uint16 // Data segment
	Name      string // Variable name
}

// UDTSym represents a user-defined type symbol (S_UDT).
type UDTSym struct {
	TypeIndex uint32 // Type index for the UDT
	Name      string // UDT name
}

// PubSym represents a public symbol (S_PUB32).
type PubSym struct {
	Flags   uint32 // Public symbol flags
	Offset  uint32 // Offset
	Segment uint16 // Segment
	Name    string // Symbol name
}

// ConstantSym represents a constant symbol (S_CONSTANT).
type ConstantSym struct {
	TypeIndex uint32 // Type index
	Value     uint64 // Constant value
	Name      string // Constant name
}

// ParseSymbols parses all symbol records from raw symbol data.
func ParseSymbols(data []byte) ([]SymbolRecord, error) {
	var symbols []SymbolRecord
	offset := 0

	// Skip the signature at the start (4 bytes)
	if len(data) >= 4 {
		sig := binary.LittleEndian.Uint32(data)
		if sig == 4 { // CV_SIGNATURE_C13
			offset = 4
		}
	}

	for offset+4 <= len(data) {
		// Read record length (2 bytes)
		recLen := binary.LittleEndian.Uint16(data[offset:])
		offset += 2

		if recLen < 2 || offset+int(recLen) > len(data) {
			break
		}

		// Read record kind (2 bytes)
		recKind := binary.LittleEndian.Uint16(data[offset:])

		sym := SymbolRecord{
			Kind: recKind,
			Data: make([]byte, recLen-2),
		}
		copy(sym.Data, data[offset+2:offset+int(recLen)])

		symbols = append(symbols, sym)
		offset += int(recLen)
	}

	return symbols, nil
}

// ParseProcSym parses a procedure symbol record.
func ParseProcSym(data []byte) (*ProcSym, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("proc symbol data too small: %d bytes", len(data))
	}

	proc := &ProcSym{
		Parent:    binary.LittleEndian.Uint32(data[0:]),
		End:       binary.LittleEndian.Uint32(data[4:]),
		Next:      binary.LittleEndian.Uint32(data[8:]),
		Length:    binary.LittleEndian.Uint32(data[12:]),
		DbgStart:  binary.LittleEndian.Uint32(data[16:]),
		DbgEnd:    binary.LittleEndian.Uint32(data[20:]),
		TypeIndex: binary.LittleEndian.Uint32(data[24:]),
		Offset:    binary.LittleEndian.Uint32(data[28:]),
		Segment:   binary.LittleEndian.Uint16(data[32:]),
		Flags:     data[34],
	}

	// Parse null-terminated name
	if len(data) > 35 {
		nameEnd := bytes.IndexByte(data[35:], 0)
		if nameEnd == -1 {
			proc.Name = string(data[35:])
		} else {
			proc.Name = string(data[35 : 35+nameEnd])
		}
	}

	return proc, nil
}

// ParseDataSym parses a data symbol record (S_GDATA32, S_LDATA32).
func ParseDataSym(data []byte) (*DataSym, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("data symbol data too small: %d bytes", len(data))
	}

	dataSym := &DataSym{
		TypeIndex: binary.LittleEndian.Uint32(data[0:]),
		Offset:    binary.LittleEndian.Uint32(data[4:]),
		Segment:   binary.LittleEndian.Uint16(data[8:]),
	}

	// Parse null-terminated name
	if len(data) > 10 {
		nameEnd := bytes.IndexByte(data[10:], 0)
		if nameEnd == -1 {
			dataSym.Name = string(data[10:])
		} else {
			dataSym.Name = string(data[10 : 10+nameEnd])
		}
	}

	return dataSym, nil
}

// ParseUDTSym parses a UDT symbol record.
func ParseUDTSym(data []byte) (*UDTSym, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("UDT symbol data too small: %d bytes", len(data))
	}

	udt := &UDTSym{
		TypeIndex: binary.LittleEndian.Uint32(data[0:]),
	}

	// Parse null-terminated name
	if len(data) > 4 {
		nameEnd := bytes.IndexByte(data[4:], 0)
		if nameEnd == -1 {
			udt.Name = string(data[4:])
		} else {
			udt.Name = string(data[4 : 4+nameEnd])
		}
	}

	return udt, nil
}

// ParsePubSym parses a public symbol record (S_PUB32).
func ParsePubSym(data []byte) (*PubSym, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("pub symbol data too small: %d bytes", len(data))
	}

	pub := &PubSym{
		Flags:   binary.LittleEndian.Uint32(data[0:]),
		Offset:  binary.LittleEndian.Uint32(data[4:]),
		Segment: binary.LittleEndian.Uint16(data[8:]),
	}

	// Parse null-terminated name
	if len(data) > 10 {
		nameEnd := bytes.IndexByte(data[10:], 0)
		if nameEnd == -1 {
			pub.Name = string(data[10:])
		} else {
			pub.Name = string(data[10 : 10+nameEnd])
		}
	}

	return pub, nil
}

// ParseConstantSym parses a constant symbol record.
func ParseConstantSym(data []byte) (*ConstantSym, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("constant symbol data too small: %d bytes", len(data))
	}

	constant := &ConstantSym{
		TypeIndex: binary.LittleEndian.Uint32(data[0:]),
	}

	// Parse numeric value
	val, consumed := parseNumeric(data[4:])
	constant.Value = val

	// Parse null-terminated name
	nameOffset := 4 + consumed
	if nameOffset < len(data) {
		nameEnd := bytes.IndexByte(data[nameOffset:], 0)
		if nameEnd == -1 {
			constant.Name = string(data[nameOffset:])
		} else {
			constant.Name = string(data[nameOffset : nameOffset+nameEnd])
		}
	}

	return constant, nil
}

// parseNumeric parses a numeric leaf value.
func parseNumeric(data []byte) (uint64, int) {
	if len(data) < 2 {
		return 0, 0
	}

	val := binary.LittleEndian.Uint16(data)
	if val < 0x8000 {
		return uint64(val), 2
	}

	switch val {
	case 0x8000: // LF_CHAR
		if len(data) < 3 {
			return 0, 0
		}
		return uint64(int8(data[2])), 3
	case 0x8001: // LF_SHORT
		if len(data) < 4 {
			return 0, 0
		}
		return uint64(int16(binary.LittleEndian.Uint16(data[2:]))), 4
	case 0x8002: // LF_USHORT
		if len(data) < 4 {
			return 0, 0
		}
		return uint64(binary.LittleEndian.Uint16(data[2:])), 4
	case 0x8003: // LF_LONG
		if len(data) < 6 {
			return 0, 0
		}
		return uint64(int32(binary.LittleEndian.Uint32(data[2:]))), 6
	case 0x8004: // LF_ULONG
		if len(data) < 6 {
			return 0, 0
		}
		return uint64(binary.LittleEndian.Uint32(data[2:])), 6
	case 0x8009: // LF_QUADWORD
		if len(data) < 10 {
			return 0, 0
		}
		return binary.LittleEndian.Uint64(data[2:]), 10
	case 0x800a: // LF_UQUADWORD
		if len(data) < 10 {
			return 0, 0
		}
		return binary.LittleEndian.Uint64(data[2:]), 10
	default:
		return 0, 0
	}
}

// SymbolKindName returns the name for a symbol kind constant.
func SymbolKindName(kind uint16) string {
	switch kind {
	case S_COMPILE:
		return "S_COMPILE"
	case S_END:
		return "S_END"
	case S_GPROC32:
		return "S_GPROC32"
	case S_LPROC32:
		return "S_LPROC32"
	case S_GPROC32_ID:
		return "S_GPROC32_ID"
	case S_LPROC32_ID:
		return "S_LPROC32_ID"
	case S_GDATA32:
		return "S_GDATA32"
	case S_LDATA32:
		return "S_LDATA32"
	case S_PUB32:
		return "S_PUB32"
	case S_UDT_NEW:
		return "S_UDT"
	case S_CONSTANT_NEW:
		return "S_CONSTANT"
	case S_PROCREF_NEW:
		return "S_PROCREF"
	case S_LPROCREF_NEW:
		return "S_LPROCREF"
	case S_COMPILE2:
		return "S_COMPILE2"
	case S_COMPILE3:
		return "S_COMPILE3"
	case S_FRAMEPROC:
		return "S_FRAMEPROC"
	case S_BLOCK32:
		return "S_BLOCK32"
	case S_LABEL32:
		return "S_LABEL32"
	case S_THUNK32:
		return "S_THUNK32"
	case S_REGREL32:
		return "S_REGREL32"
	case S_LTHREAD32:
		return "S_LTHREAD32"
	case S_GTHREAD32:
		return "S_GTHREAD32"
	case S_LOCAL:
		return "S_LOCAL"
	case S_BUILDINFO:
		return "S_BUILDINFO"
	case S_INLINESITE:
		return "S_INLINESITE"
	case S_INLINESITE_END:
		return "S_INLINESITE_END"
	case S_UNAMESPACE:
		return "S_UNAMESPACE"
	case S_SECTION:
		return "S_SECTION"
	case S_COFFGROUP:
		return "S_COFFGROUP"
	case S_ENVBLOCK:
		return "S_ENVBLOCK"
	case S_CALLSITEINFO:
		return "S_CALLSITEINFO"
	case S_FRAMECOOKIE:
		return "S_FRAMECOOKIE"
	case S_DEFRANGE_REGISTER:
		return "S_DEFRANGE_REGISTER"
	case S_DEFRANGE_FRAMEPOINTER_REL:
		return "S_DEFRANGE_FRAMEPOINTER_REL"
	case S_DEFRANGE_SUBFIELD_REGISTER:
		return "S_DEFRANGE_SUBFIELD_REGISTER"
	case S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE:
		return "S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE"
	case S_DEFRANGE_REGISTER_REL:
		return "S_DEFRANGE_REGISTER_REL"
	case S_OBJNAME_ST:
		return "S_OBJNAME"
	case S_HEAPALLOCSITE:
		return "S_HEAPALLOCSITE"
	default:
		return fmt.Sprintf("S_0x%04x", kind)
	}
}

// IsProcSymbol returns true if the kind is a procedure symbol.
func IsProcSymbol(kind uint16) bool {
	switch kind {
	case S_GPROC32, S_LPROC32, S_GPROC32_ID, S_LPROC32_ID,
		S_GPROC32_ST, S_LPROC32_ST, S_GPROCIA64, S_LPROCIA64,
		S_GPROCMIPS, S_LPROCMIPS, S_GMANPROC, S_LMANPROC,
		S_LPROC32_DPC, S_LPROC32_DPC_ID:
		return true
	}
	return false
}

// IsDataSymbol returns true if the kind is a data symbol.
func IsDataSymbol(kind uint16) bool {
	switch kind {
	case S_GDATA32, S_LDATA32, S_GDATA32_ST, S_LDATA32_ST,
		S_GMANDATA, S_LMANDATA, S_GTHREAD32, S_LTHREAD32:
		return true
	}
	return false
}

// IsGlobalSymbol returns true if the symbol has global linkage.
func IsGlobalSymbol(kind uint16) bool {
	switch kind {
	case S_GPROC32, S_GPROC32_ID, S_GPROC32_ST, S_GPROCIA64,
		S_GPROCMIPS, S_GMANPROC, S_GDATA32, S_GDATA32_ST,
		S_GMANDATA, S_GTHREAD32, S_PUB32:
		return true
	}
	return false
}
