// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package celenv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	b64 "encoding/base64"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// encodingLibrary registers hashing/encoding helpers.
//
//	sha256Hex(s)              string  Lowercase hex of SHA-256(s).
//	parseJWTUnverified(token) map     {header, payload} as parsed JSON maps;
//	                                  empty map if the token isn't a well-formed
//	                                  JWS-compact serialisation. THIS FUNCTION
//	                                  DOES NOT VERIFY ANY SIGNATURE.
//
// base64.encode / base64.decode come from ext.Encoders() in env.go.
func encodingLibrary() cel.EnvOption {
	return cel.Lib(encodingLib{})
}

type encodingLib struct{}

func (encodingLib) LibraryName() string                 { return "rv.encoding" }
func (encodingLib) ProgramOptions() []cel.ProgramOption { return nil }

func (encodingLib) CompileOptions() []cel.EnvOption {
	mapStringDyn := cel.MapType(cel.StringType, cel.DynType)

	return []cel.EnvOption{
		cel.Function("sha256Hex",
			cel.Overload("sha256Hex_string", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					sum := sha256.Sum256([]byte(stringOf(v)))
					return types.String(hex.EncodeToString(sum[:]))
				}),
			),
		),

		cel.Function("parseJWTUnverified",
			cel.Overload("parseJWTUnverified_string", []*cel.Type{cel.StringType}, mapStringDyn,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					parts := strings.Split(stringOf(v), ".")
					if len(parts) < 2 {
						return types.NewStringInterfaceMap(types.DefaultTypeAdapter, map[string]any{})
					}
					hdr, _ := decodeJWTSegment(parts[0])
					pl, _ := decodeJWTSegment(parts[1])
					return types.NewStringInterfaceMap(types.DefaultTypeAdapter, map[string]any{
						"header":  hdr,
						"payload": pl,
					})
				}),
			),
		),
	}
}

// decodeJWTSegment base64url-decodes a JWS segment and parses the JSON inside.
// Returns ({}, nil) on any error to keep CEL expressions side-effect-free.
func decodeJWTSegment(s string) (map[string]any, error) {
	raw, err := b64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// some encoders include padding; tolerate it
		raw, err = b64.URLEncoding.DecodeString(s)
		if err != nil {
			return map[string]any{}, err
		}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{}, err
	}
	return out, nil
}
