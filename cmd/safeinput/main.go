// Command safeinput provides a CLI for input sanitization.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ravisastryk/go-safeinput"
)

var version = "dev"

func main() {
	var (
		showVersion = flag.Bool("version", false, "Show version")
		context     = flag.String("context", "html", "Sanitization context (html, sql, path, shell)")
		input       = flag.String("input", "", "Input to sanitize")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("safeinput %s\n", version)
		os.Exit(0)
	}

	if *input == "" {
		fmt.Fprintln(os.Stderr, "Error: -input is required")
		flag.Usage()
		os.Exit(1)
	}

	s := safeinput.Default()
	var ctx safeinput.Context

	switch *context {
	case "html":
		ctx = safeinput.HTMLBody
	case "sql":
		ctx = safeinput.SQLIdentifier
	case "path":
		ctx = safeinput.FilePath
	case "shell":
		ctx = safeinput.ShellArg
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown context %q\n", *context)
		os.Exit(1)
	}

	result, err := s.Sanitize(*input, ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(result)
}
