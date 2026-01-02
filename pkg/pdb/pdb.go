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
	msf      *msf.MSF
	pdbInfo  *streams.PDBInfo
	tpi      *streams.TPIStream
	dbi      *streams.DBIStream
	resolver *codeview.TypeResolver

	// Cached results
	functions []Function
	variables []Variable
	publics   []PublicSymbol
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
								Length:    proc.Length,
								TypeIndex: proc.TypeIndex,
								IsGlobal:  codeview.IsGlobalSymbol(sym.Kind),
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
							Length:    proc.Length,
							TypeIndex: proc.TypeIndex,
							IsGlobal:  codeview.IsGlobalSymbol(sym.Kind),
							Module:    mod.ModuleName,
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
								TypeIndex: dataSym.TypeIndex,
								IsGlobal:  codeview.IsGlobalSymbol(sym.Kind),
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
							TypeIndex: dataSym.TypeIndex,
							IsGlobal:  codeview.IsGlobalSymbol(sym.Kind),
							Module:    mod.ModuleName,
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

	if p.dbi != nil && p.dbi.Header.PublicStreamIndex != 0xFFFF {
		stream, err := p.msf.Stream(int(p.dbi.Header.PublicStreamIndex))
		if err == nil && stream.Size() > 0 {
			data, err := stream.ReadAll()
			if err == nil {
				// Public stream has a header we need to skip
				// The actual symbols are in the symbol record stream
				_ = data
			}
		}

		// Actually, public symbols are in the SymRecordStream
		if p.dbi.Header.SymRecordStream != 0xFFFF {
			stream, err := p.msf.Stream(int(p.dbi.Header.SymRecordStream))
			if err == nil && stream.Size() > 0 {
				data, err := stream.ReadAll()
				if err == nil {
					symbols, _ := codeview.ParseSymbols(data)
					for _, sym := range symbols {
						if sym.Kind == codeview.S_PUB32 {
							pub, err := codeview.ParsePubSym(sym.Data)
							if err == nil {
								p.publics = append(p.publics, PublicSymbol{
									Name:    pub.Name,
									Offset:  pub.Offset,
									Segment: pub.Segment,
								})
							}
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
