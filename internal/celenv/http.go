package celenv

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// httpShortcutsLibrary registers small helpers around request.headers and
// request.query. These complement the convenience projections built into the
// request object:
//
//	request.header     map<string,string>        first value per (lowercase) header name
//	request.headers    map<string,list<string>>  every value per (lowercase) header name
//	request.query      map<string,string>        first value per query parameter
//	request.queries    map<string,list<string>>  every value per query parameter
//
// With those projections most lookups are just:
//
//	request.header['x-api-key'] != ''
//	request.query['debug'] == '1'
//
// The following functions add small ergonomic touches:
//
//	has(name, bucket)        bool   true if name exists in the given bucket and has a non-empty value
//	firstOr(bucket, name, d) string first value of name in bucket, or d if not present
//
// They are generic enough to apply to either headers or query buckets.
func httpShortcutsLibrary() cel.EnvOption {
	return cel.Lib(httpShortLib{})
}

type httpShortLib struct{}

func (httpShortLib) LibraryName() string                 { return "rv.http" }
func (httpShortLib) ProgramOptions() []cel.ProgramOption { return nil }

func (httpShortLib) CompileOptions() []cel.EnvOption {
	mapStringListStr := cel.MapType(cel.StringType, cel.ListType(cel.StringType))
	mapStringStr := cel.MapType(cel.StringType, cel.StringType)

	return []cel.EnvOption{
		// has(name, bucket<list<string>>) -> bool
		cel.Function("has",
			cel.Overload("has_string_mapStringListString",
				[]*cel.Type{cel.StringType, mapStringListStr}, cel.BoolType,
				cel.BinaryBinding(func(nameV, bucketV ref.Val) ref.Val {
					name := stringOf(nameV)
					b, _ := bucketV.Value().(map[string][]string)
					if b == nil {
						if alt, ok := bucketV.Value().(map[string]any); ok {
							v, ok := alt[name]
							if !ok {
								return types.Bool(false)
							}
							switch x := v.(type) {
							case []string:
								return types.Bool(anyNonEmpty(x))
							case []any:
								for _, e := range x {
									if s, ok := e.(string); ok && s != "" {
										return types.Bool(true)
									}
								}
								return types.Bool(false)
							}
							return types.Bool(false)
						}
						return types.Bool(false)
					}
					vals, ok := b[name]
					if !ok {
						return types.Bool(false)
					}
					return types.Bool(anyNonEmpty(vals))
				}),
			),
		),

		// firstOr(bucket, name, default) over either string or list buckets.
		cel.Function("firstOr",
			cel.Overload("firstOr_mapStringString_string_string",
				[]*cel.Type{mapStringStr, cel.StringType, cel.StringType}, cel.StringType,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					b, _ := args[0].Value().(map[string]string)
					name := stringOf(args[1])
					def := stringOf(args[2])
					if v, ok := b[name]; ok && v != "" {
						return types.String(v)
					}
					if alt, ok := args[0].Value().(map[string]any); ok {
						if v, ok := alt[name]; ok {
							if s, ok := v.(string); ok && s != "" {
								return types.String(s)
							}
						}
					}
					return types.String(def)
				}),
			),
			cel.Overload("firstOr_mapStringListString_string_string",
				[]*cel.Type{mapStringListStr, cel.StringType, cel.StringType}, cel.StringType,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					name := stringOf(args[1])
					def := stringOf(args[2])
					if b, ok := args[0].Value().(map[string][]string); ok {
						if vs, ok := b[name]; ok && len(vs) > 0 && vs[0] != "" {
							return types.String(vs[0])
						}
						return types.String(def)
					}
					if alt, ok := args[0].Value().(map[string]any); ok {
						if v, ok := alt[name]; ok {
							switch x := v.(type) {
							case []string:
								if len(x) > 0 && x[0] != "" {
									return types.String(x[0])
								}
							case []any:
								if len(x) > 0 {
									if s, ok := x[0].(string); ok && s != "" {
										return types.String(s)
									}
								}
							}
						}
					}
					return types.String(def)
				}),
			),
		),
	}
}

func anyNonEmpty(vs []string) bool {
	for _, v := range vs {
		if v != "" {
			return true
		}
	}
	return false
}
