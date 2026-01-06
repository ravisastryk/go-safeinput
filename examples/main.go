//go:build ignore

package main

import (
	"fmt"

	"github.com/ravisastryk/go-safeinput"
)

func main() {
	s := safeinput.Default()

	fmt.Println("=== go-safeinput Demo ===")
	fmt.Println()

	// XSS
	xss := "<script>alert('xss')</script>Hello!"
	safe, _ := s.Sanitize(xss, safeinput.HTMLBody)
	fmt.Printf("XSS Input:  %q\nXSS Output: %q\n\n", xss, safe)

	// Path Traversal
	path := "../../etc/passwd"
	_, err := s.Sanitize(path, safeinput.FilePath)
	fmt.Printf("Path Input: %q\nPath Error: %v\n\n", path, err)

	// SQL Injection
	sql := "users; DROP TABLE--"
	_, err = s.Sanitize(sql, safeinput.SQLIdentifier)
	fmt.Printf("SQL Input:  %q\nSQL Error:  %v\n\n", sql, err)

	// Valid inputs
	validPath, _ := s.Sanitize("uploads/avatar.png", safeinput.FilePath)
	validTable, _ := s.Sanitize("user_profiles", safeinput.SQLIdentifier)
	fmt.Printf("Valid path:  %q\nValid table: %q\n", validPath, validTable)
}
