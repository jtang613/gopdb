package pdb

import (
	"strings"
)

// DemangleResult contains the separated parts of a demangled name.
type DemangleResult struct {
	Name      string // The function/method name (e.g., "MyClass::MyMethod")
	Prototype string // The function prototype (e.g., "void __cdecl(int, char*)")
}

// DemangleFull attempts to demangle an MSVC decorated name and returns
// the name and prototype separately.
func DemangleFull(name string) DemangleResult {
	if name == "" {
		return DemangleResult{}
	}

	// Check for MSVC C++ mangled name (starts with ?)
	if strings.HasPrefix(name, "?") {
		return demangleMSVCFull(name)
	}

	// Check for MSVC C decorated name (starts with _ and may end with @nn)
	if strings.HasPrefix(name, "_") {
		return DemangleResult{Name: demangleCDecl(name)}
	}

	// Check for __imp_ prefix (import thunk)
	if strings.HasPrefix(name, "__imp_") {
		inner := DemangleFull(name[6:])
		if inner.Name != "" {
			inner.Name = inner.Name + " [import]"
			return inner
		}
	}

	return DemangleResult{Name: name}
}

// Demangle attempts to demangle an MSVC decorated name.
// Returns the demangled name, or the original if demangling fails.
// For separate name and prototype, use DemangleFull instead.
func Demangle(name string) string {
	result := DemangleFull(name)
	if result.Name == "" {
		return name
	}
	return result.Name
}

// demangleCDecl handles simple C decorated names like _func@8
func demangleCDecl(name string) string {
	// Remove leading underscore
	result := name[1:]

	// Check for @nn suffix (stdcall/fastcall parameter size)
	if atIdx := strings.LastIndex(result, "@"); atIdx > 0 {
		// Verify everything after @ is a number
		suffix := result[atIdx+1:]
		isNumber := true
		for _, c := range suffix {
			if c < '0' || c > '9' {
				isNumber = false
				break
			}
		}
		if isNumber && len(suffix) > 0 {
			result = result[:atIdx]
		}
	}

	return result
}

// demangleMSVCFull handles MSVC C++ mangled names and returns name and prototype separately
func demangleMSVCFull(name string) DemangleResult {
	if len(name) < 2 || name[0] != '?' {
		return DemangleResult{Name: name}
	}

	d := &msvcDemangler{
		input: name,
		pos:   1, // Skip initial '?'
		names: make([]string, 0),
	}

	return d.demangleFull()
}

type msvcDemangler struct {
	input string
	pos   int
	names []string // Back-reference table
}

func (d *msvcDemangler) demangleFull() DemangleResult {
	// Parse the qualified name
	qualName := d.parseQualifiedName()
	if qualName == "" {
		return DemangleResult{}
	}

	// Check for type encoding
	if d.pos >= len(d.input) {
		return DemangleResult{Name: qualName}
	}

	// Parse the type/encoding info (prototype)
	prototype := d.parseTypeEncoding()

	return DemangleResult{
		Name:      qualName,
		Prototype: prototype,
	}
}

func (d *msvcDemangler) parseQualifiedName() string {
	var parts []string

	for d.pos < len(d.input) {
		c := d.input[d.pos]

		// '@' terminates a name segment, '@@' terminates the qualified name
		if c == '@' {
			d.pos++
			if d.pos < len(d.input) && d.input[d.pos] == '@' {
				d.pos++
				break
			}
			continue
		}

		// Back-reference (0-9)
		if c >= '0' && c <= '9' {
			idx := int(c - '0')
			d.pos++
			if idx < len(d.names) {
				parts = append(parts, d.names[idx])
			}
			continue
		}

		// Special names
		if c == '?' {
			d.pos++
			special := d.parseSpecialName()
			if special != "" {
				parts = append(parts, special)
			}
			continue
		}

		// Regular name segment
		name := d.parseName()
		if name != "" {
			d.names = append(d.names, name)
			parts = append(parts, name)
		}
	}

	// Reverse the parts (MSVC encodes inner-to-outer)
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}

	return strings.Join(parts, "::")
}

func (d *msvcDemangler) parseName() string {
	start := d.pos
	for d.pos < len(d.input) {
		c := d.input[d.pos]
		if c == '@' || c == '?' {
			break
		}
		d.pos++
	}
	return d.input[start:d.pos]
}

func (d *msvcDemangler) parseSpecialName() string {
	if d.pos >= len(d.input) {
		return ""
	}

	c := d.input[d.pos]
	d.pos++

	switch c {
	case '0':
		return d.parseName() // Constructor
	case '1':
		return "~" + d.parseName() // Destructor
	case '2':
		return "operator new"
	case '3':
		return "operator delete"
	case '4':
		return "operator="
	case '5':
		return "operator>>"
	case '6':
		return "operator<<"
	case '7':
		return "operator!"
	case '8':
		return "operator=="
	case '9':
		return "operator!="
	case 'A':
		return "operator[]"
	case 'B':
		return "operator (cast)"
	case 'C':
		return "operator->"
	case 'D':
		return "operator*"
	case 'E':
		return "operator++"
	case 'F':
		return "operator--"
	case 'G':
		return "operator-"
	case 'H':
		return "operator+"
	case 'I':
		return "operator&"
	case 'J':
		return "operator->*"
	case 'K':
		return "operator/"
	case 'L':
		return "operator%"
	case 'M':
		return "operator<"
	case 'N':
		return "operator<="
	case 'O':
		return "operator>"
	case 'P':
		return "operator>="
	case 'Q':
		return "operator,"
	case 'R':
		return "operator()"
	case 'S':
		return "operator~"
	case 'T':
		return "operator^"
	case 'U':
		return "operator|"
	case 'V':
		return "operator&&"
	case 'W':
		return "operator||"
	case 'X':
		return "operator*="
	case 'Y':
		return "operator+="
	case 'Z':
		return "operator-="
	case '_':
		if d.pos < len(d.input) {
			c2 := d.input[d.pos]
			d.pos++
			switch c2 {
			case '0':
				return "operator/="
			case '1':
				return "operator%="
			case '2':
				return "operator>>="
			case '3':
				return "operator<<="
			case '4':
				return "operator&="
			case '5':
				return "operator|="
			case '6':
				return "operator^="
			case 'E':
				return "dynamic initializer"
			case 'F':
				return "dynamic atexit destructor"
			case 'K':
				return "operator \"\" " + d.parseName()
			}
		}
	}

	return ""
}

func (d *msvcDemangler) parseTypeEncoding() string {
	if d.pos >= len(d.input) {
		return ""
	}

	c := d.input[d.pos]

	// Function encoding
	switch c {
	case 'Y': // C function (extern "C")
		d.pos++
		return d.parseFunctionType("")
	case 'Q', 'R', 'S', 'T': // Member functions
		d.pos++
		access := d.parseAccessModifier(c)
		return d.parseFunctionType(access)
	case 'A', 'B', 'C', 'D': // Member functions with different CV
		d.pos++
		access := d.parseAccessModifier(c)
		return d.parseFunctionType(access)
	case '3': // Static member data
		d.pos++
		return ""
	case '0', '1', '2': // Member data
		d.pos++
		return ""
	}

	return ""
}

func (d *msvcDemangler) parseAccessModifier(c byte) string {
	switch c {
	case 'A', 'Q':
		return "private:"
	case 'B', 'R':
		return "private: static"
	case 'C', 'I', 'S':
		return "protected:"
	case 'D', 'J', 'T':
		return "protected: static"
	case 'E', 'K':
		return "public:"
	case 'F', 'L':
		return "public: static"
	case 'M':
		return "private: virtual"
	case 'N':
		return "protected: virtual"
	case 'O':
		return "public: virtual"
	}
	return ""
}

func (d *msvcDemangler) parseFunctionType(access string) string {
	if d.pos >= len(d.input) {
		return access
	}

	// Parse calling convention
	callingConv := d.parseCallingConvention()

	// Parse return type
	returnType := d.parseType()

	// Parse arguments
	args := d.parseArguments()

	result := ""
	if returnType != "" {
		result = returnType
	}
	if callingConv != "" {
		if result != "" {
			result += " "
		}
		result += callingConv
	}
	if args != "" {
		result += "(" + args + ")"
	}

	return result
}

func (d *msvcDemangler) parseCallingConvention() string {
	if d.pos >= len(d.input) {
		return ""
	}

	c := d.input[d.pos]
	d.pos++

	switch c {
	case 'A':
		return "__cdecl"
	case 'B':
		return "__cdecl __export"
	case 'C':
		return "__pascal"
	case 'D':
		return "__pascal __export"
	case 'E':
		return "__thiscall"
	case 'F':
		return "__thiscall __export"
	case 'G':
		return "__stdcall"
	case 'H':
		return "__stdcall __export"
	case 'I':
		return "__fastcall"
	case 'J':
		return "__fastcall __export"
	case 'K':
		return ""
	case 'L':
		return ""
	case 'M':
		return "__clrcall"
	case 'Q':
		return "__vectorcall"
	}

	d.pos-- // Not a calling convention
	return ""
}

func (d *msvcDemangler) parseType() string {
	if d.pos >= len(d.input) {
		return ""
	}

	c := d.input[d.pos]
	d.pos++

	switch c {
	// Primitive types
	case 'X':
		return "void"
	case 'C':
		return "signed char"
	case 'D':
		return "char"
	case 'E':
		return "unsigned char"
	case 'F':
		return "short"
	case 'G':
		return "unsigned short"
	case 'H':
		return "int"
	case 'I':
		return "unsigned int"
	case 'J':
		return "long"
	case 'K':
		return "unsigned long"
	case 'M':
		return "float"
	case 'N':
		return "double"
	case 'O':
		return "long double"
	case '_':
		if d.pos < len(d.input) {
			c2 := d.input[d.pos]
			d.pos++
			switch c2 {
			case 'J':
				return "__int64"
			case 'K':
				return "unsigned __int64"
			case 'N':
				return "bool"
			case 'W':
				return "wchar_t"
			case 'S':
				return "char16_t"
			case 'U':
				return "char32_t"
			}
		}
	// Pointer types
	case 'P':
		inner := d.parseType()
		return inner + "*"
	case 'Q':
		inner := d.parseType()
		return inner + "* const"
	case 'A':
		inner := d.parseType()
		return inner + "&"
	case 'B':
		inner := d.parseType()
		return "volatile " + inner
	// User-defined types
	case 'U', 'V', 'T':
		// Skip until @@ for class/struct/union name
		return d.parseClassName()
	case '@':
		return "" // End of type
	case 'Z':
		return "..." // Varargs
	}

	d.pos--
	return ""
}

func (d *msvcDemangler) parseClassName() string {
	start := d.pos
	depth := 0
	for d.pos < len(d.input) {
		c := d.input[d.pos]
		if c == '@' {
			if d.pos+1 < len(d.input) && d.input[d.pos+1] == '@' {
				d.pos += 2
				break
			}
			depth++
		}
		d.pos++
	}
	name := d.input[start : d.pos-2]
	// Reverse namespace order
	parts := strings.Split(name, "@")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, "::")
}

func (d *msvcDemangler) parseArguments() string {
	var args []string
	for d.pos < len(d.input) {
		c := d.input[d.pos]
		if c == '@' || c == 'Z' {
			d.pos++
			break
		}
		arg := d.parseType()
		if arg == "" {
			break
		}
		args = append(args, arg)
		if len(args) > 20 { // Safety limit
			break
		}
	}
	return strings.Join(args, ", ")
}
