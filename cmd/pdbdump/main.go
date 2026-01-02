// pdbdump is a CLI tool for extracting information from Microsoft PDB files.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/jtang613/gopdb/pkg/pdb"
)

func main() {
	// Flags
	showInfo := flag.Bool("info", false, "Show PDB file information")
	showFunctions := flag.Bool("functions", false, "List all functions")
	showVariables := flag.Bool("variables", false, "List all variables")
	showTypes := flag.Bool("types", false, "List all named types")
	showPublics := flag.Bool("publics", false, "List all public symbols")
	showModules := flag.Bool("modules", false, "List all modules")
	showAll := flag.Bool("all", false, "Show all information")
	prettyPrint := flag.Bool("pretty", false, "Pretty-print JSON output")
	typeIndex := flag.Uint("type", 0, "Show details for a specific type index")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <pdb-file>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -info file.pdb\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -functions -pretty file.pdb\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -all file.pdb\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -type 0x1000 file.pdb\n", os.Args[0])
	}

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	pdbPath := flag.Arg(0)

	// Open PDB
	p, err := pdb.Open(pdbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening PDB: %v\n", err)
		os.Exit(1)
	}
	defer p.Close()

	// Helper for JSON output
	outputJSON := func(v interface{}) {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(false) // Don't escape &, <, > as \u0026, \u003c, \u003e
		if *prettyPrint {
			encoder.SetIndent("", "  ")
		}
		if err := encoder.Encode(v); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
	}

	// Handle type lookup
	if *typeIndex > 0 {
		ti := p.ResolveType(uint32(*typeIndex))
		if ti == nil {
			fmt.Fprintf(os.Stderr, "Type 0x%x not found\n", *typeIndex)
			os.Exit(1)
		}
		outputJSON(ti)
		return
	}

	// Default to showing info if no flags specified
	if !*showInfo && !*showFunctions && !*showVariables && !*showTypes && !*showPublics && !*showModules && !*showAll {
		*showInfo = true
	}

	// Build output
	result := make(map[string]interface{})

	if *showInfo || *showAll {
		result["info"] = p.Info()
	}

	if *showModules || *showAll {
		result["modules"] = p.Modules()
	}

	if *showFunctions || *showAll {
		result["functions"] = p.Functions()
	}

	if *showVariables || *showAll {
		result["variables"] = p.Variables()
	}

	if *showTypes || *showAll {
		result["types"] = p.Types()
	}

	if *showPublics || *showAll {
		result["public_symbols"] = p.PublicSymbols()
	}

	outputJSON(result)
}
