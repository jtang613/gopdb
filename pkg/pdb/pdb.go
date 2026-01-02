package pdb

import (
	"fmt"

	"github.com/jtang613/gopdb/pkg/pdb/codeview"
	"github.com/jtang613/gopdb/pkg/pdb/msf"
	"github.com/jtang613/gopdb/pkg/pdb/streams"
)

// Stream indices
const (
	StreamPDB = 1 // PDB info stream
	StreamTPI = 2 // Type info stream
	StreamDBI = 3 // Debug info stream
	StreamIPI = 4 // ID info stream
)

// PDB represents an opened PDB file.
type PDB struct {
	msf            *msf.MSF
	pdbInfo        *streams.PDBInfo
	tpi            *streams.TPIStream
	dbi            *streams.DBIStream
	resolver       *codeview.TypeResolver
	sectionHeaders []streams.PESectionHeader

	// Cached results
	functions []Function
	variables []Variable
	publics   []PublicSymbol
	sections  []SectionInfo
}

// Open opens a PDB file and parses its core structures.
func Open(path string) (*PDB, error) {
	m, err := msf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open MSF: %w", err)
	}

	pdb := &PDB{msf: m}

	// Parse PDB info stream
	if m.NumStreams() > StreamPDB {
		reader, err := m.StreamReader(StreamPDB)
		if err == nil {
			pdb.pdbInfo, _ = streams.ReadPDBInfo(reader)
		}
	}

	// Parse TPI stream
	if m.NumStreams() > StreamTPI {
		stream, err := m.Stream(StreamTPI)
		if err == nil && stream.Size() > 0 {
			data, err := stream.ReadAll()
			if err == nil {
				pdb.tpi, _ = streams.ReadTPIStream(data)
				pdb.resolver = codeview.NewTypeResolver(pdb.tpi)
			}
		}
	}

	// Parse DBI stream
	if m.NumStreams() > StreamDBI {
		stream, err := m.Stream(StreamDBI)
		if err == nil && stream.Size() > 0 {
			data, err := stream.ReadAll()
			if err == nil {
				pdb.dbi, _ = streams.ReadDBIStream(data)
			}
		}
	}

	// Load section headers from optional debug header stream
	if pdb.dbi != nil && pdb.dbi.DebugHeader != nil {
		secHdrStream := int(pdb.dbi.DebugHeader.SectionHdr)
		if secHdrStream != 0xFFFF && m.NumStreams() > secHdrStream {
			stream, err := m.Stream(secHdrStream)
			if err == nil && stream.Size() > 0 {
				data, err := stream.ReadAll()
				if err == nil {
					pdb.sectionHeaders = streams.ParseSectionHeaders(data)
				}
			}
		}
	}

	return pdb, nil
}

// Close closes the PDB file.
func (p *PDB) Close() error {
	if p.msf != nil {
		return p.msf.Close()
	}
	return nil
}

// Info returns basic PDB file information.
func (p *PDB) Info() *PDBInfo {
	info := &PDBInfo{
		Streams: p.msf.NumStreams(),
	}

	if p.pdbInfo != nil {
		info.GUID = p.pdbInfo.GUIDString()
		info.Age = p.pdbInfo.Age
		info.Version = p.pdbInfo.Version
		info.NamedStreams = p.pdbInfo.NamedStreams
	}

	if p.dbi != nil {
		info.Machine = streams.MachineTypeName(p.dbi.Header.Machine)
	}

	return info
}

// Functions returns all functions found in the PDB.
func (p *PDB) Functions() []Function {
	if p.functions != nil {
		return p.functions
	}

	p.functions = make([]Function, 0)

	// Parse global symbols stream
	if p.dbi != nil && p.dbi.Header.SymRecordStream != 0xFFFF {
		stream, err := p.msf.Stream(int(p.dbi.Header.SymRecordStream))
		if err == nil && stream.Size() > 0 {
			data, err := stream.ReadAll()
			if err == nil {
				symbols, _ := codeview.ParseSymbols(data)
				for _, sym := range symbols {
					if codeview.IsProcSymbol(sym.Kind) {
						proc, err := codeview.ParseProcSym(sym.Data)
						if err == nil {
							fn := Function{
								Name:      proc.Name,
								Offset:    proc.Offset,
								Segment:   proc.Segment,
								RVA:       p.SegmentToRVA(proc.Segment, proc.Offset),
								Length:    proc.Length,
								TypeIndex: proc.TypeIndex,
								IsGlobal:  codeview.IsGlobalSymbol(sym.Kind),
							}
							if demangled := DemangleFull(proc.Name); demangled.Name != proc.Name {
								fn.DemangledName = demangled.Name
								fn.Prototype = demangled.Prototype
							}
							if p.resolver != nil {
								fn.Signature = p.resolver.ResolveType(proc.TypeIndex)
							}
							p.functions = append(p.functions, fn)
						}
					}
				}
			}
		}
	}

	// Parse module symbols
	if p.dbi != nil {
		for _, mod := range p.dbi.Modules {
			if !mod.HasSymbols() {
				continue
			}

			stream, err := p.msf.Stream(int(mod.ModuleSymStream))
			if err != nil || stream.Size() == 0 {
				continue
			}

			data, err := stream.ReadAll()
			if err != nil {
				continue
			}

			// Only read SymByteSize bytes for symbols
			symData := data
			if uint32(len(data)) > mod.SymByteSize {
				symData = data[:mod.SymByteSize]
			}

			symbols, _ := codeview.ParseSymbols(symData)
			for _, sym := range symbols {
				if codeview.IsProcSymbol(sym.Kind) {
					proc, err := codeview.ParseProcSym(sym.Data)
					if err == nil {
						fn := Function{
							Name:      proc.Name,
							Offset:    proc.Offset,
							Segment:   proc.Segment,
							RVA:       p.SegmentToRVA(proc.Segment, proc.Offset),
							Length:    proc.Length,
							TypeIndex: proc.TypeIndex,
							IsGlobal:  codeview.IsGlobalSymbol(sym.Kind),
							Module:    mod.ModuleName,
						}
						if demangled := DemangleFull(proc.Name); demangled.Name != proc.Name {
							fn.DemangledName = demangled.Name
							fn.Prototype = demangled.Prototype
						}
						if p.resolver != nil {
							fn.Signature = p.resolver.ResolveType(proc.TypeIndex)
						}
						p.functions = append(p.functions, fn)
					}
				}
			}
		}
	}

	return p.functions
}

// Variables returns all global/static variables found in the PDB.
func (p *PDB) Variables() []Variable {
	if p.variables != nil {
		return p.variables
	}

	p.variables = make([]Variable, 0)

	// Parse global symbols stream
	if p.dbi != nil && p.dbi.Header.SymRecordStream != 0xFFFF {
		stream, err := p.msf.Stream(int(p.dbi.Header.SymRecordStream))
		if err == nil && stream.Size() > 0 {
			data, err := stream.ReadAll()
			if err == nil {
				symbols, _ := codeview.ParseSymbols(data)
				for _, sym := range symbols {
					if codeview.IsDataSymbol(sym.Kind) {
						dataSym, err := codeview.ParseDataSym(sym.Data)
						if err == nil {
							v := Variable{
								Name:      dataSym.Name,
								Offset:    dataSym.Offset,
								Segment:   dataSym.Segment,
								RVA:       p.SegmentToRVA(dataSym.Segment, dataSym.Offset),
								TypeIndex: dataSym.TypeIndex,
								IsGlobal:  codeview.IsGlobalSymbol(sym.Kind),
							}
							if demangled := DemangleFull(dataSym.Name); demangled.Name != dataSym.Name {
								v.DemangledName = demangled.Name
								v.Prototype = demangled.Prototype
							}
							if p.resolver != nil {
								v.TypeName = p.resolver.ResolveType(dataSym.TypeIndex)
							}
							p.variables = append(p.variables, v)
						}
					}
				}
			}
		}
	}

	// Parse module symbols for static variables
	if p.dbi != nil {
		for _, mod := range p.dbi.Modules {
			if !mod.HasSymbols() {
				continue
			}

			stream, err := p.msf.Stream(int(mod.ModuleSymStream))
			if err != nil || stream.Size() == 0 {
				continue
			}

			data, err := stream.ReadAll()
			if err != nil {
				continue
			}

			symData := data
			if uint32(len(data)) > mod.SymByteSize {
				symData = data[:mod.SymByteSize]
			}

			symbols, _ := codeview.ParseSymbols(symData)
			for _, sym := range symbols {
				if codeview.IsDataSymbol(sym.Kind) {
					dataSym, err := codeview.ParseDataSym(sym.Data)
					if err == nil {
						v := Variable{
							Name:      dataSym.Name,
							Offset:    dataSym.Offset,
							Segment:   dataSym.Segment,
							RVA:       p.SegmentToRVA(dataSym.Segment, dataSym.Offset),
							TypeIndex: dataSym.TypeIndex,
							IsGlobal:  codeview.IsGlobalSymbol(sym.Kind),
							Module:    mod.ModuleName,
						}
						if demangled := DemangleFull(dataSym.Name); demangled.Name != dataSym.Name {
							v.DemangledName = demangled.Name
							v.Prototype = demangled.Prototype
						}
						if p.resolver != nil {
							v.TypeName = p.resolver.ResolveType(dataSym.TypeIndex)
						}
						p.variables = append(p.variables, v)
					}
				}
			}
		}
	}

	return p.variables
}

// PublicSymbols returns all public symbols.
func (p *PDB) PublicSymbols() []PublicSymbol {
	if p.publics != nil {
		return p.publics
	}

	p.publics = make([]PublicSymbol, 0)

	if p.dbi != nil && p.dbi.Header.SymRecordStream != 0xFFFF {
		stream, err := p.msf.Stream(int(p.dbi.Header.SymRecordStream))
		if err == nil && stream.Size() > 0 {
			data, err := stream.ReadAll()
			if err == nil {
				symbols, _ := codeview.ParseSymbols(data)
				for _, sym := range symbols {
					if sym.Kind == codeview.S_PUB32 {
						pub, err := codeview.ParsePubSym(sym.Data)
						if err == nil {
							ps := PublicSymbol{
								Name:    pub.Name,
								Offset:  pub.Offset,
								Segment: pub.Segment,
								RVA:     p.SegmentToRVA(pub.Segment, pub.Offset),
							}
							if demangled := DemangleFull(pub.Name); demangled.Name != pub.Name {
								ps.DemangledName = demangled.Name
								ps.Prototype = demangled.Prototype
							}
							p.publics = append(p.publics, ps)
						}
					}
				}
			}
		}
	}

	return p.publics
}

// Types returns all named types from the TPI stream.
func (p *PDB) Types() []TypeInfo {
	var types []TypeInfo

	if p.tpi == nil {
		return types
	}

	for _, rec := range p.tpi.TypeRecords {
		switch rec.Kind {
		case streams.LF_STRUCTURE, streams.LF_STRUCTURE_newformat,
			streams.LF_CLASS, streams.LF_CLASS_newformat,
			streams.LF_UNION, streams.LF_UNION_newformat:
			parsed := p.resolver.ParseStructureType(&rec)
			if parsed != nil && parsed.Name != "" {
				ti := TypeInfo{
					Index:     parsed.Index,
					Kind:      parsed.KindName,
					Name:      parsed.Name,
					Size:      parsed.Size,
					Signature: parsed.Signature,
				}
				for _, m := range parsed.Members {
					ti.Members = append(ti.Members, Member{
						Name:     m.Name,
						TypeName: m.TypeName,
						Offset:   m.Offset,
					})
				}
				types = append(types, ti)
			}

		case streams.LF_ENUM, streams.LF_ENUM_newformat:
			parsed := p.resolver.ParseEnumType(&rec)
			if parsed != nil && parsed.Name != "" {
				ti := TypeInfo{
					Index:     parsed.Index,
					Kind:      "enum",
					Name:      parsed.Name,
					Signature: parsed.Signature,
				}
				for _, m := range parsed.Members {
					ti.Members = append(ti.Members, Member{
						Name:     m.Name,
						TypeName: m.TypeName,
						Offset:   m.Offset,
					})
				}
				types = append(types, ti)
			}
		}
	}

	return types
}

// ResolveType resolves a type index to a TypeInfo.
func (p *PDB) ResolveType(index uint32) *TypeInfo {
	if p.tpi == nil {
		return nil
	}

	if index < streams.TypeIndexBegin {
		// Built-in type
		return &TypeInfo{
			Index:     index,
			Kind:      "builtin",
			Name:      streams.GetBuiltinTypeName(index),
			Signature: streams.GetBuiltinTypeName(index),
		}
	}

	rec := p.tpi.GetType(index)
	if rec == nil {
		return nil
	}

	switch rec.Kind {
	case streams.LF_STRUCTURE, streams.LF_STRUCTURE_newformat,
		streams.LF_CLASS, streams.LF_CLASS_newformat,
		streams.LF_UNION, streams.LF_UNION_newformat:
		parsed := p.resolver.ParseStructureType(rec)
		if parsed != nil {
			ti := &TypeInfo{
				Index:     parsed.Index,
				Kind:      parsed.KindName,
				Name:      parsed.Name,
				Size:      parsed.Size,
				Signature: parsed.Signature,
			}
			for _, m := range parsed.Members {
				ti.Members = append(ti.Members, Member{
					Name:     m.Name,
					TypeName: m.TypeName,
					Offset:   m.Offset,
				})
			}
			return ti
		}

	case streams.LF_ENUM, streams.LF_ENUM_newformat:
		parsed := p.resolver.ParseEnumType(rec)
		if parsed != nil {
			ti := &TypeInfo{
				Index:     parsed.Index,
				Kind:      "enum",
				Name:      parsed.Name,
				Signature: parsed.Signature,
			}
			for _, m := range parsed.Members {
				ti.Members = append(ti.Members, Member{
					Name:     m.Name,
					TypeName: m.TypeName,
					Offset:   m.Offset,
				})
			}
			return ti
		}
	}

	// For other types, return basic info
	return &TypeInfo{
		Index:     index,
		Kind:      streams.LeafKindName(rec.Kind),
		Signature: p.resolver.ResolveType(index),
	}
}

// Modules returns information about compiled modules.
func (p *PDB) Modules() []ModuleInfo {
	if p.dbi == nil {
		return nil
	}

	modules := make([]ModuleInfo, len(p.dbi.Modules))
	for i, mod := range p.dbi.Modules {
		modules[i] = ModuleInfo{
			Name:         mod.ModuleName,
			ObjectFile:   mod.ObjFileName,
			SymbolStream: mod.ModuleSymStream,
			SymbolSize:   mod.SymByteSize,
			SourceFiles:  mod.SourceFileCount,
		}
	}
	return modules
}

// TypeCount returns the number of types in the TPI stream.
func (p *PDB) TypeCount() int {
	if p.tpi == nil {
		return 0
	}
	return p.tpi.NumTypes()
}

// Sections returns the PE section information.
// Uses PE section headers when available (more accurate), falls back to section map.
func (p *PDB) Sections() []SectionInfo {
	if p.sections != nil {
		return p.sections
	}

	p.sections = make([]SectionInfo, 0)

	// Prefer PE section headers (from debug stream) if available
	if len(p.sectionHeaders) > 0 {
		for i, hdr := range p.sectionHeaders {
			p.sections = append(p.sections, SectionInfo{
				Index:  uint16(i + 1), // 1-based index
				Name:   hdr.SectionName(),
				Offset: hdr.VirtualAddress, // RVA base
				Length: hdr.VirtualSize,
			})
		}
		return p.sections
	}

	// Fall back to section map
	if p.dbi == nil || len(p.dbi.SectionMap) == 0 {
		return p.sections
	}

	for i, entry := range p.dbi.SectionMap {
		// Skip entries with no length (often the first entry is a placeholder)
		if entry.SectionLength == 0 && i == 0 {
			continue
		}
		p.sections = append(p.sections, SectionInfo{
			Index:  uint16(i + 1), // 1-based index
			Offset: entry.Offset,
			Length: entry.SectionLength,
		})
	}

	return p.sections
}

// SegmentToRVA converts a segment:offset pair to an RVA (Relative Virtual Address).
// Segment is 1-based (as used in PDB symbols).
// Returns 0 if the segment is invalid or section headers are not available.
func (p *PDB) SegmentToRVA(segment uint16, offset uint32) uint32 {
	// Prefer PE section headers (from debug stream) if available
	if len(p.sectionHeaders) > 0 {
		if segment == 0 || int(segment) > len(p.sectionHeaders) {
			return 0
		}
		return p.sectionHeaders[segment-1].VirtualAddress + offset
	}

	// Fall back to section map
	if p.dbi == nil || len(p.dbi.SectionMap) == 0 {
		return 0
	}

	// Segment is 1-based, so subtract 1 for index
	if segment == 0 || int(segment) > len(p.dbi.SectionMap) {
		return 0
	}

	entry := p.dbi.SectionMap[segment-1]
	return entry.Offset + offset
}
