// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package celenv

import (
	"regexp"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// stringLibrary registers shell-style glob helpers. The standard `ext.Strings()`
// extension is already enabled from env.go and provides .split, .replace,
// .lower(), .upper(), .indexOf(), .lastIndexOf(), .substring(), .charAt(),
// format() and .join().
//
//	glob(s, pattern)          bool
//	globAny(s, [patterns])    bool
//
// Pattern syntax:
//
//   - matches any sequence of characters except '/'
//     **       matches any sequence of characters INCLUDING '/'
//     ?        matches exactly one character
//     [abc]    character class
//
// The patterns are translated to RE2 internally and compiled once per pattern.
func stringLibrary() cel.EnvOption {
	return cel.Lib(stringLib{})
}

type stringLib struct{}

func (stringLib) LibraryName() string                 { return "rv.strings" }
func (stringLib) ProgramOptions() []cel.ProgramOption { return nil }

func (stringLib) CompileOptions() []cel.EnvOption {
	listOfStrings := cel.ListType(cel.StringType)
	return []cel.EnvOption{
		cel.Function("glob",
			cel.Overload("glob_string_string", []*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
				cel.BinaryBinding(func(sv, pv ref.Val) ref.Val {
					return types.Bool(matchGlob(stringOf(sv), stringOf(pv)))
				}),
			),
		),
		cel.Function("globAny",
			cel.Overload("globAny_string_listofstring", []*cel.Type{cel.StringType, listOfStrings}, cel.BoolType,
				cel.BinaryBinding(func(sv, psv ref.Val) ref.Val {
					s := stringOf(sv)
					raws, ok := psv.Value().([]ref.Val)
					if !ok {
						if anys, ok := psv.Value().([]any); ok {
							for _, a := range anys {
								if p, ok := a.(string); ok && matchGlob(s, p) {
									return types.Bool(true)
								}
							}
						}
						return types.Bool(false)
					}
					for _, r := range raws {
						if p, ok := r.Value().(string); ok && matchGlob(s, p) {
							return types.Bool(true)
						}
					}
					return types.Bool(false)
				}),
			),
		),
	}
}

// globRE2 translates a shell-style glob into an anchored RE2 pattern.
func globRE2(g string) string {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(g); i++ {
		c := g[i]
		switch c {
		case '*':
			if i+1 < len(g) && g[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '[':
			// Character classes pass through unchanged up to the next ']'.
			j := strings.IndexByte(g[i:], ']')
			if j == -1 {
				b.WriteString(regexp.QuoteMeta(string(c)))
				continue
			}
			b.WriteString(g[i : i+j+1])
			i += j
		case '.', '+', '(', ')', '|', '^', '$', '\\':
			b.WriteString(regexp.QuoteMeta(string(c)))
		default:
			b.WriteByte(c)
		}
	}
	b.WriteString("$")
	return b.String()
}

var globCache sync.Map // map[string]*regexp.Regexp

func matchGlob(s, pattern string) bool {
	if v, ok := globCache.Load(pattern); ok {
		return v.(*regexp.Regexp).MatchString(s)
	}
	re, err := regexp.Compile(globRE2(pattern))
	if err != nil {
		return false
	}
	globCache.Store(pattern, re)
	return re.MatchString(s)
}
