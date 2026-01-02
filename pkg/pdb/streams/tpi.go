package streams

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// TPI Stream versions
const (
	TPIStreamVersion40  = 19950410
	TPIStreamVersion41  = 19951122
	TPIStreamVersion50  = 19961031
	TPIStreamVersionV70 = 19990903
	TPIStreamVersionV80 = 20040203
)

// First type index (built-in types are below this)
const TypeIndexBegin = 0x1000

// TPIHeader is the header of the TPI stream.
type TPIHeader struct {
	Version              uint32
	HeaderSize           uint32
	TypeIndexBegin       uint32
	TypeIndexEnd         uint32
	TypeRecordBytes      uint32
	HashStreamIndex      uint16
	HashAuxStreamIndex   uint16
	HashKeySize          uint32
	NumHashBuckets       uint32
	HashValueBufferOffset int32
	HashValueBufferLength uint32
	IndexOffsetBufferOffset int32
	IndexOffsetBufferLength uint32
	HashAdjBufferOffset  int32
	HashAdjBufferLength  uint32
}

// TPIStream represents the parsed TPI (Type Info) stream.
type TPIStream struct {
	Header      TPIHeader
	TypeRecords []TypeRecord
	typeMap     map[uint32]*TypeRecord // Type index to record
}

// TypeRecord represents a single type record.
type TypeRecord struct {
	Index  uint32 // Type index
	Kind   uint16 // LF_* type kind
	Data   []byte // Raw record data (excluding length and kind)
}

// ReadTPIStream parses the TPI stream from raw bytes.
func ReadTPIStream(data []byte) (*TPIStream, error) {
	r := bytes.NewReader(data)

	var header TPIHeader
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read TPI header: %w", err)
	}

	// Validate version
	if header.Version != TPIStreamVersionV80 && header.Version != TPIStreamVersionV70 {
		return nil, fmt.Errorf("unsupported TPI version: %d", header.Version)
	}

	// Read type records
	recordData := make([]byte, header.TypeRecordBytes)
	if _, err := io.ReadFull(r, recordData); err != nil {
		return nil, fmt.Errorf("failed to read type records: %w", err)
	}

	tpi := &TPIStream{
		Header:  header,
		typeMap: make(map[uint32]*TypeRecord),
	}

	// Parse individual type records
	offset := 0
	typeIndex := header.TypeIndexBegin
	for offset < len(recordData) && typeIndex < header.TypeIndexEnd {
		if offset+2 > len(recordData) {
			break
		}

		// Read record length (2 bytes)
		recLen := binary.LittleEndian.Uint16(recordData[offset:])
		offset += 2

		if offset+int(recLen) > len(recordData) {
			break
		}

		// Read record kind (2 bytes, part of the record)
		if recLen < 2 {
			typeIndex++
			continue
		}

		recKind := binary.LittleEndian.Uint16(recordData[offset:])

		record := TypeRecord{
			Index: typeIndex,
			Kind:  recKind,
			Data:  make([]byte, recLen-2),
		}
		copy(record.Data, recordData[offset+2:offset+int(recLen)])

		tpi.TypeRecords = append(tpi.TypeRecords, record)
		tpi.typeMap[typeIndex] = &tpi.TypeRecords[len(tpi.TypeRecords)-1]

		offset += int(recLen)
		typeIndex++
	}

	return tpi, nil
}

// GetType returns the type record for the given type index.
func (t *TPIStream) GetType(index uint32) *TypeRecord {
	return t.typeMap[index]
}

// NumTypes returns the number of type records.
func (t *TPIStream) NumTypes() int {
	return len(t.TypeRecords)
}

// TypeCount returns the number of types (TypeIndexEnd - TypeIndexBegin).
func (t *TPIStream) TypeCount() uint32 {
	return t.Header.TypeIndexEnd - t.Header.TypeIndexBegin
}

// LF_* type leaf constants
const (
	// Leaf types for type records
	LF_MODIFIER     = 0x1001
	LF_POINTER      = 0x1002
	LF_ARRAY        = 0x1003
	LF_CLASS        = 0x1004
	LF_STRUCTURE    = 0x1005
	LF_UNION        = 0x1006
	LF_ENUM         = 0x1007
	LF_PROCEDURE    = 0x1008
	LF_MFUNCTION    = 0x1009
	LF_VTSHAPE      = 0x000a
	LF_COBOL0       = 0x100a
	LF_COBOL1       = 0x100b
	LF_BARRAY       = 0x100c
	LF_LABEL        = 0x000e
	LF_NULL         = 0x000f
	LF_NOTTRAN      = 0x0010
	LF_DIMARRAY     = 0x100d
	LF_VFTPATH      = 0x100e
	LF_PRECOMP      = 0x100f
	LF_ENDPRECOMP   = 0x0014
	LF_OEM          = 0x0015
	LF_TYPESERVER_ST = 0x0016

	LF_SKIP         = 0x1200
	LF_ARGLIST      = 0x1201
	LF_DEFARG       = 0x1202
	LF_FIELDLIST    = 0x1203
	LF_DERIVED      = 0x1204
	LF_BITFIELD     = 0x1205
	LF_METHODLIST   = 0x1206
	LF_DIMCONU      = 0x1207
	LF_DIMCONLU     = 0x1208
	LF_DIMVARU      = 0x1209
	LF_DIMVARLU     = 0x120a

	LF_BCLASS       = 0x1400
	LF_VBCLASS      = 0x1401
	LF_IVBCLASS     = 0x1402
	LF_ENUMERATE    = 0x1403
	LF_FRIENDFCN    = 0x1404
	LF_INDEX        = 0x1405
	LF_MEMBER       = 0x1406
	LF_STMEMBER     = 0x1407
	LF_METHOD       = 0x1408
	LF_NESTTYPE     = 0x1409
	LF_VFUNCTAB     = 0x140a
	LF_FRIENDCLS    = 0x140b
	LF_ONEMETHOD    = 0x140c
	LF_VFUNCOFF     = 0x140d
	LF_NESTTYPEEX   = 0x140e
	LF_MEMBERMODIFY = 0x140f

	// New types in later versions
	LF_ARRAY_ST     = 0x1003
	LF_CLASS_ST     = 0x1004
	LF_STRUCTURE_ST = 0x1005
	LF_UNION_ST     = 0x1006
	LF_ENUM_ST      = 0x1007

	LF_POINTER_16t  = 0x0100
	LF_ARRAY_16t    = 0x0003
	LF_CLASS_16t    = 0x0004
	LF_STRUCTURE_16t= 0x0005
	LF_UNION_16t    = 0x0006
	LF_ENUM_16t     = 0x0007
	LF_PROCEDURE_16t= 0x0008
	LF_MFUNCTION_16t= 0x0009
	LF_ARGLIST_16t  = 0x0001
	LF_FIELDLIST_16t= 0x0003

	// More leaf types
	LF_TYPESERVER   = 0x1016
	LF_ENUMERATE_ST = 0x1403
	LF_ARRAY_newformat      = 0x1503
	LF_CLASS_newformat      = 0x1504
	LF_STRUCTURE_newformat  = 0x1505
	LF_UNION_newformat      = 0x1506
	LF_ENUM_newformat       = 0x1507
	LF_POINTER_newformat    = 0x1002
	LF_PROCEDURE_newformat  = 0x1008
	LF_MEMBER_newformat     = 0x150d
	LF_STMEMBER_newformat   = 0x150e
	LF_METHOD_newformat     = 0x150f
	LF_NESTTYPE_newformat   = 0x1510
	LF_ONEMETHOD_newformat  = 0x1511

	LF_FUNC_ID      = 0x1601
	LF_MFUNC_ID     = 0x1602
	LF_BUILDINFO    = 0x1603
	LF_SUBSTR_LIST  = 0x1604
	LF_STRING_ID    = 0x1605
	LF_UDT_SRC_LINE = 0x1606
	LF_UDT_MOD_SRC_LINE = 0x1607
)

// Built-in type constants (type indices < 0x1000)
// Mode (bits 8-11)
const (
	TM_DIRECT   = 0 // Not a pointer
	TM_NPTR     = 1 // Near pointer
	TM_FPTR     = 2 // Far pointer
	TM_HPTR     = 3 // Huge pointer
	TM_NPTR32   = 4 // 32-bit near pointer
	TM_FPTR32   = 5 // 32-bit far pointer
	TM_NPTR64   = 6 // 64-bit near pointer
	TM_NPTR128  = 7 // 128-bit near pointer
)

// Kind (bits 0-7)
const (
	T_NOTYPE    = 0x0000
	T_ABS       = 0x0001
	T_SEGMENT   = 0x0002
	T_VOID      = 0x0003
	T_CURRENCY  = 0x0004
	T_NBASICSTR = 0x0005
	T_FBASICSTR = 0x0006
	T_NOTTRANS  = 0x0007
	T_HRESULT   = 0x0008

	T_CHAR      = 0x0010
	T_SHORT     = 0x0011
	T_LONG      = 0x0012
	T_QUAD      = 0x0013
	T_OCT       = 0x0014

	T_UCHAR     = 0x0020
	T_USHORT    = 0x0021
	T_ULONG     = 0x0022
	T_UQUAD     = 0x0023
	T_UOCT      = 0x0024

	T_BOOL08    = 0x0030
	T_BOOL16    = 0x0031
	T_BOOL32    = 0x0032
	T_BOOL64    = 0x0033

	T_REAL32    = 0x0040
	T_REAL64    = 0x0041
	T_REAL80    = 0x0042
	T_REAL128   = 0x0043
	T_REAL48    = 0x0044
	T_REAL32PP  = 0x0045
	T_REAL16    = 0x0046

	T_CPLX32    = 0x0050
	T_CPLX64    = 0x0051
	T_CPLX80    = 0x0052
	T_CPLX128   = 0x0053

	T_BIT       = 0x0060
	T_PASCHAR   = 0x0061
	T_BOOL32FF  = 0x0062

	T_INT1      = 0x0068
	T_UINT1     = 0x0069
	T_RCHAR     = 0x0070
	T_WCHAR     = 0x0071
	T_INT2      = 0x0072
	T_UINT2     = 0x0073
	T_INT4      = 0x0074
	T_UINT4     = 0x0075
	T_INT8      = 0x0076
	T_UINT8     = 0x0077
	T_INT16     = 0x0078
	T_UINT16    = 0x0079
	T_CHAR16    = 0x007a
	T_CHAR32    = 0x007b
	T_CHAR8     = 0x007c
)

// GetBuiltinTypeName returns the name of a built-in type index.
func GetBuiltinTypeName(typeIdx uint32) string {
	if typeIdx >= TypeIndexBegin {
		return ""
	}

	kind := typeIdx & 0xFF
	mode := (typeIdx >> 8) & 0xF

	baseName := ""
	switch kind {
	case T_NOTYPE:
		baseName = "<no type>"
	case T_VOID:
		baseName = "void"
	case T_CHAR:
		baseName = "char"
	case T_SHORT:
		baseName = "short"
	case T_LONG:
		baseName = "long"
	case T_QUAD:
		baseName = "int64"
	case T_UCHAR:
		baseName = "unsigned char"
	case T_USHORT:
		baseName = "unsigned short"
	case T_ULONG:
		baseName = "unsigned long"
	case T_UQUAD:
		baseName = "uint64"
	case T_BOOL08:
		baseName = "bool"
	case T_BOOL32:
		baseName = "BOOL"
	case T_REAL32:
		baseName = "float"
	case T_REAL64:
		baseName = "double"
	case T_REAL80:
		baseName = "long double"
	case T_INT1:
		baseName = "int8"
	case T_UINT1:
		baseName = "uint8"
	case T_RCHAR:
		baseName = "char"
	case T_WCHAR:
		baseName = "wchar_t"
	case T_INT2:
		baseName = "int16"
	case T_UINT2:
		baseName = "uint16"
	case T_INT4:
		baseName = "int32"
	case T_UINT4:
		baseName = "uint32"
	case T_INT8:
		baseName = "int64"
	case T_UINT8:
		baseName = "uint64"
	case T_HRESULT:
		baseName = "HRESULT"
	default:
		baseName = fmt.Sprintf("builtin_0x%04x", typeIdx)
	}

	// Apply pointer mode
	switch mode {
	case TM_DIRECT:
		return baseName
	case TM_NPTR, TM_NPTR32:
		return baseName + "*"
	case TM_NPTR64:
		return baseName + "*"
	case TM_FPTR, TM_FPTR32:
		return baseName + " far*"
	default:
		return baseName + "*"
	}
}

// LeafKindName returns the name for a LF_* constant.
func LeafKindName(kind uint16) string {
	switch kind {
	case LF_MODIFIER:
		return "LF_MODIFIER"
	case LF_POINTER:
		return "LF_POINTER"
	case LF_ARRAY, LF_ARRAY_newformat:
		return "LF_ARRAY"
	case LF_CLASS, LF_CLASS_newformat:
		return "LF_CLASS"
	case LF_STRUCTURE, LF_STRUCTURE_newformat:
		return "LF_STRUCTURE"
	case LF_UNION, LF_UNION_newformat:
		return "LF_UNION"
	case LF_ENUM, LF_ENUM_newformat:
		return "LF_ENUM"
	case LF_PROCEDURE:
		return "LF_PROCEDURE"
	case LF_MFUNCTION:
		return "LF_MFUNCTION"
	case LF_ARGLIST:
		return "LF_ARGLIST"
	case LF_FIELDLIST:
		return "LF_FIELDLIST"
	case LF_BITFIELD:
		return "LF_BITFIELD"
	case LF_MEMBER, LF_MEMBER_newformat:
		return "LF_MEMBER"
	case LF_ENUMERATE:
		return "LF_ENUMERATE"
	case LF_NESTTYPE, LF_NESTTYPE_newformat:
		return "LF_NESTTYPE"
	case LF_METHOD, LF_METHOD_newformat:
		return "LF_METHOD"
	case LF_ONEMETHOD, LF_ONEMETHOD_newformat:
		return "LF_ONEMETHOD"
	case LF_FUNC_ID:
		return "LF_FUNC_ID"
	case LF_MFUNC_ID:
		return "LF_MFUNC_ID"
	case LF_BUILDINFO:
		return "LF_BUILDINFO"
	case LF_STRING_ID:
		return "LF_STRING_ID"
	case LF_UDT_SRC_LINE:
		return "LF_UDT_SRC_LINE"
	default:
		return fmt.Sprintf("LF_0x%04x", kind)
	}
}

// ParseNumeric parses a numeric leaf value from the data.
// Returns the value and the number of bytes consumed.
func ParseNumeric(data []byte) (uint64, int) {
	if len(data) < 2 {
		return 0, 0
	}

	val := binary.LittleEndian.Uint16(data)
	if val < 0x8000 {
		return uint64(val), 2
	}

	// Encoded numeric follows
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

// ParseString parses a null-terminated string from data.
// Returns the string and number of bytes consumed (including null).
func ParseString(data []byte) (string, int) {
	idx := bytes.IndexByte(data, 0)
	if idx == -1 {
		return string(data), len(data)
	}
	return string(data[:idx]), idx + 1
}
