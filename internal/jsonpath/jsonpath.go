// Package jsonpath implements a tiny subset of JSONPath used by request-validator.
//
// Supported syntax (a deliberate, minimal subset):
//
//	$              - root (optional, implicit)
//	.name          - child key
//	['name']       - child key (allows quoted keys with special chars)
//	["name"]       - child key (double-quoted variant)
//	[N]            - array index (negative allowed, -1 == last)
//	[*]            - all elements of an array, or all values of an object
//	..name         - recursive descent: every "name" at any depth
//
// Anything else is rejected at parse time. The intent is to be predictable
// and fast, not to ship a full JSONPath engine.
package jsonpath

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Expr is a compiled selector ready to be evaluated against a parsed JSON tree.
type Expr struct {
	steps []step
}

type stepKind int

const (
	stepKey stepKind = iota
	stepIndex
	stepWildcard
	stepRecursive
)

type step struct {
	kind stepKind
	name string // for stepKey, stepRecursive
	idx  int    // for stepIndex
}

var (
	reChild     = regexp.MustCompile(`^\.([A-Za-z_][A-Za-z0-9_\-]*)`)
	reRecursive = regexp.MustCompile(`^\.\.([A-Za-z_][A-Za-z0-9_\-]*)`)
	reBracket   = regexp.MustCompile(`^\[(\*|-?\d+|'[^']*'|"[^"]*")\]`)
)

// Compile parses the expression once. The result is safe for concurrent use.
func Compile(expr string) (*Expr, error) {
	if expr == "" {
		return nil, errors.New("empty jsonpath expression")
	}
	rest := strings.TrimPrefix(expr, "$")
	out := &Expr{}
	for len(rest) > 0 {
		switch {
		case strings.HasPrefix(rest, ".."):
			m := reRecursive.FindStringSubmatch(rest)
			if m == nil {
				return nil, fmt.Errorf("invalid recursive descent near %q", rest)
			}
			out.steps = append(out.steps, step{kind: stepRecursive, name: m[1]})
			rest = rest[len(m[0]):]
		case strings.HasPrefix(rest, "."):
			m := reChild.FindStringSubmatch(rest)
			if m == nil {
				return nil, fmt.Errorf("invalid child accessor near %q", rest)
			}
			out.steps = append(out.steps, step{kind: stepKey, name: m[1]})
			rest = rest[len(m[0]):]
		case strings.HasPrefix(rest, "["):
			m := reBracket.FindStringSubmatch(rest)
			if m == nil {
				return nil, fmt.Errorf("invalid bracket accessor near %q", rest)
			}
			inner := m[1]
			switch {
			case inner == "*":
				out.steps = append(out.steps, step{kind: stepWildcard})
			case strings.HasPrefix(inner, "'") || strings.HasPrefix(inner, `"`):
				out.steps = append(out.steps, step{kind: stepKey, name: inner[1 : len(inner)-1]})
			default:
				n, err := strconv.Atoi(inner)
				if err != nil {
					return nil, fmt.Errorf("invalid array index %q", inner)
				}
				out.steps = append(out.steps, step{kind: stepIndex, idx: n})
			}
			rest = rest[len(m[0]):]
		default:
			// Allow shorthand: "redirect_uris[*]" as if written ".redirect_uris[*]".
			if isIdentStart(rest[0]) {
				rest = "." + rest
				continue
			}
			return nil, fmt.Errorf("invalid jsonpath fragment near %q", rest)
		}
	}
	return out, nil
}

func isIdentStart(b byte) bool {
	return b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// Eval applies the expression to the given root node and returns every value
// that matches. Order follows document order from a depth-first traversal.
func (e *Expr) Eval(root any) []any {
	nodes := []any{root}
	for _, s := range e.steps {
		next := make([]any, 0, len(nodes))
		for _, n := range nodes {
			switch s.kind {
			case stepKey:
				if m, ok := n.(map[string]any); ok {
					if v, ok := m[s.name]; ok {
						next = append(next, v)
					}
				}
			case stepIndex:
				if a, ok := n.([]any); ok {
					i := s.idx
					if i < 0 {
						i = len(a) + i
					}
					if i >= 0 && i < len(a) {
						next = append(next, a[i])
					}
				}
			case stepWildcard:
				switch v := n.(type) {
				case []any:
					next = append(next, v...)
				case map[string]any:
					// Iterate in a stable order for deterministic results.
					keys := make([]string, 0, len(v))
					for k := range v {
						keys = append(keys, k)
					}
					sortStrings(keys)
					for _, k := range keys {
						next = append(next, v[k])
					}
				}
			case stepRecursive:
				collectRecursive(n, s.name, &next)
			}
		}
		nodes = next
	}
	return nodes
}

func collectRecursive(n any, name string, out *[]any) {
	switch v := n.(type) {
	case map[string]any:
		if got, ok := v[name]; ok {
			*out = append(*out, got)
		}
		for _, vv := range v {
			collectRecursive(vv, name, out)
		}
	case []any:
		for _, vv := range v {
			collectRecursive(vv, name, out)
		}
	}
}

// sortStrings: lightweight inline sort to avoid pulling sort package only for
// determinism - kept here in case we want to swap algorithm later.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
