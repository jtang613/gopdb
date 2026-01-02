package codeview

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/jtang613/gopdb/pkg/pdb/streams"
)

// TypeResolver provides type resolution from TPI stream.
type TypeResolver struct {
	tpi *streams.TPIStream
}

// NewTypeResolver creates a new type resolver.
func NewTypeResolver(tpi *streams.TPIStream) *TypeResolver {
	return &TypeResolver{tpi: tpi}
}

// ResolveType resolves a type index to a human-readable string.
func (r *TypeResolver) ResolveType(typeIdx uint32) string {
	// Handle built-in types
	if typeIdx < streams.TypeIndexBegin {
		return streams.GetBuiltinTypeName(typeIdx)
	}

	// Look up the type record
	if r.tpi == nil {
		return fmt.Sprintf("type_0x%x", typeIdx)
	}

	rec := r.tpi.GetType(typeIdx)
	if rec == nil {
		return fmt.Sprintf("type_0x%x", typeIdx)
	}

	return r.resolveTypeRecord(rec)
}

// resolveTypeRecord converts a type record to a string.
func (r *TypeResolver) resolveTypeRecord(rec *streams.TypeRecord) string {
	switch rec.Kind {
	case streams.LF_POINTER:
		return r.resolvePointer(rec.Data)
	case streams.LF_ARRAY, streams.LF_ARRAY_newformat:
		return r.resolveArray(rec.Data)
	case streams.LF_PROCEDURE:
		return r.resolveProcedure(rec.Data)
	case streams.LF_MFUNCTION:
		return r.resolveMemberFunction(rec.Data)
	case streams.LF_STRUCTURE, streams.LF_STRUCTURE_newformat:
		return r.resolveStructure(rec.Data, "struct")
	case streams.LF_CLASS, streams.LF_CLASS_newformat:
		return r.resolveStructure(rec.Data, "class")
	case streams.LF_UNION, streams.LF_UNION_newformat:
		return r.resolveStructure(rec.Data, "union")
	case streams.LF_ENUM, streams.LF_ENUM_newformat:
		return r.resolveEnum(rec.Data)
	case streams.LF_MODIFIER:
		return r.resolveModifier(rec.Data)
	case streams.LF_ARGLIST:
		return r.resolveArgList(rec.Data)
	case streams.LF_BITFIELD:
		return r.resolveBitfield(rec.Data)
	default:
		return fmt.Sprintf("type_0x%x", rec.Index)
	}
}

// resolvePointer resolves LF_POINTER type.
func (r *TypeResolver) resolvePointer(data []byte) string {
	if len(data) < 8 {
		return "ptr<?>"
	}

	underlyingType := binary.LittleEndian.Uint32(data[0:])
	attrs := binary.LittleEndian.Uint32(data[4:])

	ptrKind := (attrs >> 0) & 0x1F
	ptrMode := (attrs >> 5) & 0x07
	isConst := (attrs >> 10) & 0x01
	isVolatile := (attrs >> 11) & 0x01

	underlyingStr := r.ResolveType(underlyingType)

	var suffix string
	switch ptrKind {
	case 0: // Near pointer
		suffix = "*"
	case 1: // Far pointer
		suffix = " far*"
	case 2: // Huge pointer
		suffix = " huge*"
	case 4: // 32-bit pointer
		suffix = "*"
	case 6: // 64-bit pointer
		suffix = "*"
	case 10: // Near 64-bit pointer
		suffix = "*"
	default:
		suffix = "*"
	}

	// Handle reference vs pointer
	switch ptrMode {
	case 1: // L-value reference
		suffix = "&"
	case 2: // R-value reference
		suffix = "&&"
	}

	result := underlyingStr + suffix
	if isConst != 0 {
		result = "const " + result
	}
	if isVolatile != 0 {
		result = "volatile " + result
	}

	return result
}

// resolveArray resolves LF_ARRAY type.
func (r *TypeResolver) resolveArray(data []byte) string {
	if len(data) < 8 {
		return "array<?>"
	}

	elemType := binary.LittleEndian.Uint32(data[0:])
	// idxType := binary.LittleEndian.Uint32(data[4:])

	elemStr := r.ResolveType(elemType)

	// Parse size (numeric leaf)
	size, consumed := streams.ParseNumeric(data[8:])
	_ = consumed

	if size > 0 {
		return fmt.Sprintf("%s[%d]", elemStr, size)
	}
	return fmt.Sprintf("%s[]", elemStr)
}

// resolveProcedure resolves LF_PROCEDURE type.
func (r *TypeResolver) resolveProcedure(data []byte) string {
	if len(data) < 12 {
		return "func<?>"
	}

	retType := binary.LittleEndian.Uint32(data[0:])
	callConv := data[4]
	// funcAttr := data[5]
	numParams := binary.LittleEndian.Uint16(data[6:])
	argListIdx := binary.LittleEndian.Uint32(data[8:])

	retStr := r.ResolveType(retType)
	argStr := r.ResolveType(argListIdx)

	_ = numParams
	_ = callConv

	return fmt.Sprintf("%s (%s)", retStr, argStr)
}

// resolveMemberFunction resolves LF_MFUNCTION type.
func (r *TypeResolver) resolveMemberFunction(data []byte) string {
	if len(data) < 24 {
		return "mfunc<?>"
	}

	retType := binary.LittleEndian.Uint32(data[0:])
	classType := binary.LittleEndian.Uint32(data[4:])
	thisType := binary.LittleEndian.Uint32(data[8:])
	callConv := data[12]
	// funcAttr := data[13]
	numParams := binary.LittleEndian.Uint16(data[14:])
	argListIdx := binary.LittleEndian.Uint32(data[16:])
	// thisAdjust := binary.LittleEndian.Uint32(data[20:])

	retStr := r.ResolveType(retType)
	classStr := r.ResolveType(classType)
	argStr := r.ResolveType(argListIdx)

	_ = numParams
	_ = callConv
	_ = thisType

	return fmt.Sprintf("%s::%s (%s)", classStr, retStr, argStr)
}

// resolveStructure resolves LF_STRUCTURE, LF_CLASS, LF_UNION types.
func (r *TypeResolver) resolveStructure(data []byte, kind string) string {
	if len(data) < 18 {
		return fmt.Sprintf("%s<?>", kind)
	}

	// count := binary.LittleEndian.Uint16(data[0:])
	// property := binary.LittleEndian.Uint16(data[2:])
	// fieldList := binary.LittleEndian.Uint32(data[4:])
	// derived := binary.LittleEndian.Uint32(data[8:])
	// vshape := binary.LittleEndian.Uint32(data[12:])

	// Parse size (numeric leaf)
	_, consumed := streams.ParseNumeric(data[16:])

	// Parse name
	nameOffset := 16 + consumed
	if nameOffset < len(data) {
		name, _ := streams.ParseString(data[nameOffset:])
		if name != "" {
			return name
		}
	}

	return kind
}

// resolveEnum resolves LF_ENUM type.
func (r *TypeResolver) resolveEnum(data []byte) string {
	if len(data) < 12 {
		return "enum<?>"
	}

	// count := binary.LittleEndian.Uint16(data[0:])
	// property := binary.LittleEndian.Uint16(data[2:])
	// underlyingType := binary.LittleEndian.Uint32(data[4:])
	// fieldList := binary.LittleEndian.Uint32(data[8:])

	// Parse name
	if len(data) > 12 {
		name, _ := streams.ParseString(data[12:])
		if name != "" {
			return name
		}
	}

	return "enum"
}

// resolveModifier resolves LF_MODIFIER type.
func (r *TypeResolver) resolveModifier(data []byte) string {
	if len(data) < 6 {
		return "mod<?>"
	}

	modifiedType := binary.LittleEndian.Uint32(data[0:])
	modifiers := binary.LittleEndian.Uint16(data[4:])

	modStr := r.ResolveType(modifiedType)

	if modifiers&0x01 != 0 {
		modStr = "const " + modStr
	}
	if modifiers&0x02 != 0 {
		modStr = "volatile " + modStr
	}
	if modifiers&0x04 != 0 {
		modStr = "unaligned " + modStr
	}

	return modStr
}

// resolveArgList resolves LF_ARGLIST type.
func (r *TypeResolver) resolveArgList(data []byte) string {
	if len(data) < 4 {
		return ""
	}

	count := binary.LittleEndian.Uint32(data[0:])
	if count == 0 {
		return "void"
	}

	var args []string
	offset := 4
	for i := uint32(0); i < count && offset+4 <= len(data); i++ {
		argType := binary.LittleEndian.Uint32(data[offset:])
		args = append(args, r.ResolveType(argType))
		offset += 4
	}

	result := ""
	for i, arg := range args {
		if i > 0 {
			result += ", "
		}
		result += arg
	}
	return result
}

// resolveBitfield resolves LF_BITFIELD type.
func (r *TypeResolver) resolveBitfield(data []byte) string {
	if len(data) < 6 {
		return "bitfield<?>"
	}

	baseType := binary.LittleEndian.Uint32(data[0:])
	length := data[4]
	position := data[5]

	baseStr := r.ResolveType(baseType)
	return fmt.Sprintf("%s : %d (pos %d)", baseStr, length, position)
}

// ParsedType represents a fully parsed type.
type ParsedType struct {
	Index     uint32
	Kind      uint16
	KindName  string
	Name      string
	Size      uint64
	Signature string
	Members   []ParsedMember
}

// ParsedMember represents a member of a struct/class/union.
type ParsedMember struct {
	Name     string
	TypeIdx  uint32
	TypeName string
	Offset   uint64
}

// ParseStructureType parses a structure/class/union type fully.
func (r *TypeResolver) ParseStructureType(rec *streams.TypeRecord) *ParsedType {
	if rec == nil || len(rec.Data) < 18 {
		return nil
	}

	data := rec.Data
	count := binary.LittleEndian.Uint16(data[0:])
	property := binary.LittleEndian.Uint16(data[2:])
	fieldListIdx := binary.LittleEndian.Uint32(data[4:])
	// derived := binary.LittleEndian.Uint32(data[8:])
	// vshape := binary.LittleEndian.Uint32(data[12:])

	// Parse size
	size, consumed := streams.ParseNumeric(data[16:])

	// Parse name
	nameOffset := 16 + consumed
	name := ""
	if nameOffset < len(data) {
		name, _ = streams.ParseString(data[nameOffset:])
	}

	var kindName string
	switch rec.Kind {
	case streams.LF_STRUCTURE, streams.LF_STRUCTURE_newformat:
		kindName = "struct"
	case streams.LF_CLASS, streams.LF_CLASS_newformat:
		kindName = "class"
	case streams.LF_UNION, streams.LF_UNION_newformat:
		kindName = "union"
	}

	parsed := &ParsedType{
		Index:     rec.Index,
		Kind:      rec.Kind,
		KindName:  kindName,
		Name:      name,
		Size:      size,
		Signature: fmt.Sprintf("%s %s", kindName, name),
	}

	// Skip forward declaration
	if property&0x80 != 0 {
		return parsed
	}

	// Parse field list if present
	if fieldListIdx != 0 && fieldListIdx >= streams.TypeIndexBegin && r.tpi != nil {
		fieldRec := r.tpi.GetType(fieldListIdx)
		if fieldRec != nil && fieldRec.Kind == streams.LF_FIELDLIST {
			parsed.Members = r.parseFieldList(fieldRec.Data)
		}
	}

	_ = count
	return parsed
}

// parseFieldList parses an LF_FIELDLIST record.
func (r *TypeResolver) parseFieldList(data []byte) []ParsedMember {
	var members []ParsedMember
	offset := 0

	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}

		// Read leaf kind
		leafKind := binary.LittleEndian.Uint16(data[offset:])
		offset += 2

		switch leafKind {
		case streams.LF_MEMBER, streams.LF_MEMBER_newformat:
			if offset+8 > len(data) {
				return members
			}
			// attrs := binary.LittleEndian.Uint16(data[offset:])
			offset += 2
			typeIdx := binary.LittleEndian.Uint32(data[offset:])
			offset += 4

			// Parse offset (numeric leaf)
			memberOffset, consumed := streams.ParseNumeric(data[offset:])
			offset += consumed

			// Parse name
			if offset >= len(data) {
				break
			}
			name, nameLen := streams.ParseString(data[offset:])
			offset += nameLen

			members = append(members, ParsedMember{
				Name:     name,
				TypeIdx:  typeIdx,
				TypeName: r.ResolveType(typeIdx),
				Offset:   memberOffset,
			})

		case streams.LF_STMEMBER, streams.LF_STMEMBER_newformat:
			// Static member
			if offset+6 > len(data) {
				return members
			}
			offset += 2 // attrs
			typeIdx := binary.LittleEndian.Uint32(data[offset:])
			offset += 4

			if offset >= len(data) {
				break
			}
			name, nameLen := streams.ParseString(data[offset:])
			offset += nameLen

			members = append(members, ParsedMember{
				Name:     name,
				TypeIdx:  typeIdx,
				TypeName: r.ResolveType(typeIdx) + " (static)",
				Offset:   0,
			})

		case streams.LF_METHOD, streams.LF_METHOD_newformat:
			// Method list
			if offset+6 > len(data) {
				return members
			}
			// count := binary.LittleEndian.Uint16(data[offset:])
			offset += 2
			// mlist := binary.LittleEndian.Uint32(data[offset:])
			offset += 4

			if offset >= len(data) {
				break
			}
			_, nameLen := streams.ParseString(data[offset:])
			offset += nameLen

		case streams.LF_ONEMETHOD, streams.LF_ONEMETHOD_newformat:
			// Single method
			if offset+6 > len(data) {
				return members
			}
			// attrs := binary.LittleEndian.Uint16(data[offset:])
			offset += 2
			// typeIdx := binary.LittleEndian.Uint32(data[offset:])
			offset += 4

			if offset >= len(data) {
				break
			}
			_, nameLen := streams.ParseString(data[offset:])
			offset += nameLen

		case streams.LF_NESTTYPE, streams.LF_NESTTYPE_newformat:
			// Nested type
			if offset+6 > len(data) {
				return members
			}
			offset += 2 // padding
			// typeIdx := binary.LittleEndian.Uint32(data[offset:])
			offset += 4

			if offset >= len(data) {
				break
			}
			_, nameLen := streams.ParseString(data[offset:])
			offset += nameLen

		case streams.LF_BCLASS:
			// Base class
			if offset+8 > len(data) {
				return members
			}
			offset += 2 // attrs
			typeIdx := binary.LittleEndian.Uint32(data[offset:])
			offset += 4

			baseOffset, consumed := streams.ParseNumeric(data[offset:])
			offset += consumed

			members = append(members, ParsedMember{
				Name:     "(base)",
				TypeIdx:  typeIdx,
				TypeName: r.ResolveType(typeIdx),
				Offset:   baseOffset,
			})

		case streams.LF_VFUNCTAB:
			// Virtual function table pointer
			if offset+6 > len(data) {
				return members
			}
			offset += 2 // padding
			// typeIdx := binary.LittleEndian.Uint32(data[offset:])
			offset += 4

		case streams.LF_ENUMERATE:
			// Enum value
			if offset+2 > len(data) {
				return members
			}
			// attrs := binary.LittleEndian.Uint16(data[offset:])
			offset += 2

			_, consumed := streams.ParseNumeric(data[offset:])
			offset += consumed

			if offset >= len(data) {
				break
			}
			_, nameLen := streams.ParseString(data[offset:])
			offset += nameLen

		case streams.LF_INDEX:
			// Continuation
			if offset+6 > len(data) {
				return members
			}
			offset += 2 // padding
			contIdx := binary.LittleEndian.Uint32(data[offset:])
			offset += 4

			// Follow the continuation
			if contIdx >= streams.TypeIndexBegin && r.tpi != nil {
				contRec := r.tpi.GetType(contIdx)
				if contRec != nil && contRec.Kind == streams.LF_FIELDLIST {
					contMembers := r.parseFieldList(contRec.Data)
					members = append(members, contMembers...)
				}
			}

		default:
			// Unknown leaf type - try to skip padding
			if leafKind >= 0xF0 && leafKind <= 0xFF {
				// Padding byte
				offset += int(leafKind) & 0x0F
				offset -= 2 // We already consumed 2 bytes for the "kind"
				if offset < 0 {
					offset = 0
				}
			} else {
				// Unknown, stop parsing
				return members
			}
		}

		// Align to 4-byte boundary
		offset = alignTo(offset, 4)
	}

	return members
}

// alignTo aligns offset to the given alignment.
func alignTo(offset, align int) int {
	if align <= 0 {
		return offset
	}
	return (offset + align - 1) & ^(align - 1)
}

// ParseEnumType parses an enum type.
func (r *TypeResolver) ParseEnumType(rec *streams.TypeRecord) *ParsedType {
	if rec == nil || len(rec.Data) < 12 {
		return nil
	}

	data := rec.Data
	count := binary.LittleEndian.Uint16(data[0:])
	// property := binary.LittleEndian.Uint16(data[2:])
	underlyingType := binary.LittleEndian.Uint32(data[4:])
	fieldListIdx := binary.LittleEndian.Uint32(data[8:])

	// Parse name
	name := ""
	if len(data) > 12 {
		name, _ = streams.ParseString(data[12:])
	}

	parsed := &ParsedType{
		Index:     rec.Index,
		Kind:      rec.Kind,
		KindName:  "enum",
		Name:      name,
		Signature: fmt.Sprintf("enum %s : %s", name, r.ResolveType(underlyingType)),
	}

	// Parse enum values from field list
	if fieldListIdx != 0 && fieldListIdx >= streams.TypeIndexBegin && r.tpi != nil {
		fieldRec := r.tpi.GetType(fieldListIdx)
		if fieldRec != nil && fieldRec.Kind == streams.LF_FIELDLIST {
			parsed.Members = r.parseEnumFieldList(fieldRec.Data)
		}
	}

	_ = count
	return parsed
}

// parseEnumFieldList parses enum values from a field list.
func (r *TypeResolver) parseEnumFieldList(data []byte) []ParsedMember {
	var members []ParsedMember
	offset := 0

	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}

		leafKind := binary.LittleEndian.Uint16(data[offset:])
		offset += 2

		if leafKind == streams.LF_ENUMERATE {
			if offset+2 > len(data) {
				break
			}
			// attrs := binary.LittleEndian.Uint16(data[offset:])
			offset += 2

			value, consumed := streams.ParseNumeric(data[offset:])
			offset += consumed

			if offset >= len(data) {
				break
			}
			name := ""
			idx := bytes.IndexByte(data[offset:], 0)
			if idx == -1 {
				name = string(data[offset:])
				offset = len(data)
			} else {
				name = string(data[offset : offset+idx])
				offset += idx + 1
			}

			members = append(members, ParsedMember{
				Name:     name,
				TypeName: fmt.Sprintf("%d", value),
				Offset:   value,
			})
		} else if leafKind == streams.LF_INDEX {
			// Continuation
			if offset+6 > len(data) {
				break
			}
			offset += 2 // padding
			contIdx := binary.LittleEndian.Uint32(data[offset:])
			offset += 4

			if contIdx >= streams.TypeIndexBegin && r.tpi != nil {
				contRec := r.tpi.GetType(contIdx)
				if contRec != nil && contRec.Kind == streams.LF_FIELDLIST {
					contMembers := r.parseEnumFieldList(contRec.Data)
					members = append(members, contMembers...)
				}
			}
		} else if leafKind >= 0xF0 && leafKind <= 0xFF {
			// Padding
			offset += int(leafKind) & 0x0F
			offset -= 2
			if offset < 0 {
				offset = 0
			}
		} else {
			break
		}

		offset = alignTo(offset, 4)
	}

	return members
}
