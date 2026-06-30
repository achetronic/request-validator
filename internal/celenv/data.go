// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package celenv

import (
	"encoding/json"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	yamlv3 "gopkg.in/yaml.v3"

	"request-validator/internal/jsonpath"
)

// dataLibrary registers structured-data helpers:
//
//	jsonPath(root, "$.foo[*]")  list<dyn>   Apply our JSONPath-lite subset.
//	parseJSON(s)                dyn         Parse a JSON string into a CEL value.
//	parseYAML(s)                dyn         Parse a YAML string into a CEL value.
//
// parseJSON / parseYAML return an empty map ({}) when the input is empty or
// malformed. This keeps expressions side-effect-free: a feed that hasn't been
// populated yet behaves like an empty document instead of raising an error.
func dataLibrary() cel.EnvOption {
	return cel.Lib(dataLib{})
}

type dataLib struct{}

func (dataLib) LibraryName() string                 { return "rv.data" }
func (dataLib) ProgramOptions() []cel.ProgramOption { return nil }

func (dataLib) CompileOptions() []cel.EnvOption {
	listOfDyn := cel.ListType(cel.DynType)
	return []cel.EnvOption{
		cel.Function("jsonPath",
			cel.Overload("jsonPath_dyn_string", []*cel.Type{cel.DynType, cel.StringType}, listOfDyn,
				cel.BinaryBinding(func(rootv, pathv ref.Val) ref.Val {
					path := stringOf(pathv)
					expr, err := jsonpath.Compile(path)
					if err != nil {
						return types.NewDynamicList(types.DefaultTypeAdapter, []any{})
					}
					raw := rootv.Value()
					out := expr.Eval(raw)
					return types.NewDynamicList(types.DefaultTypeAdapter, out)
				}),
			),
		),

		cel.Function("parseJSON",
			// Accept dyn so a `facts.<name>` value that hasn't been
			// populated yet (nil) or isn't a string yields a sensible empty
			// map instead of "no such overload".
			cel.Overload("parseJSON_dyn", []*cel.Type{cel.DynType}, cel.DynType,
				cel.UnaryBinding(parseJSONFromAny),
			),
		),

		cel.Function("parseYAML",
			cel.Overload("parseYAML_dyn", []*cel.Type{cel.DynType}, cel.DynType,
				cel.UnaryBinding(parseYAMLFromAny),
			),
		),
	}
}

func parseJSONFromAny(v ref.Val) ref.Val {
	s, ok := v.Value().(string)
	if !ok || s == "" {
		return emptyMap()
	}
	var raw any
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return emptyMap()
	}
	return types.DefaultTypeAdapter.NativeToValue(normalise(raw))
}

func parseYAMLFromAny(v ref.Val) ref.Val {
	s, ok := v.Value().(string)
	if !ok || s == "" {
		return emptyMap()
	}
	var raw any
	if err := yamlv3.Unmarshal([]byte(s), &raw); err != nil {
		return emptyMap()
	}
	return types.DefaultTypeAdapter.NativeToValue(normalise(raw))
}

func emptyMap() ref.Val {
	return types.DefaultTypeAdapter.NativeToValue(map[string]any{})
}

// normalise rewrites map[any]any (yaml.v3 default for some maps) and recurses
// into lists/maps so CEL adapters see a consistent shape.
func normalise(v any) any {
	switch x := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[fmt.Sprint(k)] = normalise(vv)
		}
		return out
	case map[string]any:
		for k, vv := range x {
			x[k] = normalise(vv)
		}
		return x
	case []any:
		for i, vv := range x {
			x[i] = normalise(vv)
		}
		return x
	}
	return v
}
