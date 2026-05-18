package celenv

import (
	"net"
	"net/url"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// netLibrary registers IP / CIDR / URL functions:
//
//	inCIDR(ip, [cidrs])       bool   IP membership in any of the listed CIDRs/IPs
//	ipFamily(ip)              string "ipv4" | "ipv6" | ""
//	isPrivateIP(ip)           bool   RFC1918 / RFC4193 / link-local
//	isLoopbackIP(ip)          bool   127.0.0.0/8 or ::1
//	parseURL(s)               map    {scheme, host, port, path, query, fragment, userinfo}
func netLibrary() cel.EnvOption {
	return cel.Lib(netLib{})
}

type netLib struct{}

func (netLib) LibraryName() string                 { return "rv.net" }
func (netLib) ProgramOptions() []cel.ProgramOption { return nil }

func (netLib) CompileOptions() []cel.EnvOption {
	listOfStrings := cel.ListType(cel.StringType)
	mapStringDyn := cel.MapType(cel.StringType, cel.DynType)

	return []cel.EnvOption{
		cel.Function("inCIDR",
			cel.Overload("inCIDR_string_listofstring",
				[]*cel.Type{cel.StringType, listOfStrings},
				cel.BoolType,
				cel.BinaryBinding(func(ipv, cidrsv ref.Val) ref.Val {
					ipStr, _ := ipv.Value().(string)
					ip := net.ParseIP(ipStr)
					if ip == nil {
						return types.Bool(false)
					}
					raws, ok := cidrsv.Value().([]ref.Val)
					if !ok {
						// fall back to []any (some builds wrap differently)
						if anys, ok := cidrsv.Value().([]any); ok {
							for _, a := range anys {
								if s, ok := a.(string); ok && cidrContains(s, ip) {
									return types.Bool(true)
								}
							}
							return types.Bool(false)
						}
						return types.Bool(false)
					}
					for _, r := range raws {
						if s, ok := r.Value().(string); ok && cidrContains(s, ip) {
							return types.Bool(true)
						}
					}
					return types.Bool(false)
				}),
			),
		),

		cel.Function("ipFamily",
			cel.Overload("ipFamily_string", []*cel.Type{cel.StringType}, cel.StringType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					ip := net.ParseIP(stringOf(v))
					if ip == nil {
						return types.String("")
					}
					if ip.To4() != nil {
						return types.String("ipv4")
					}
					return types.String("ipv6")
				}),
			),
		),

		cel.Function("isPrivateIP",
			cel.Overload("isPrivateIP_string", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					ip := net.ParseIP(stringOf(v))
					if ip == nil {
						return types.Bool(false)
					}
					return types.Bool(ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast())
				}),
			),
		),

		cel.Function("isLoopbackIP",
			cel.Overload("isLoopbackIP_string", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					ip := net.ParseIP(stringOf(v))
					if ip == nil {
						return types.Bool(false)
					}
					return types.Bool(ip.IsLoopback())
				}),
			),
		),

		cel.Function("parseURL",
			cel.Overload("parseURL_string", []*cel.Type{cel.StringType}, mapStringDyn,
				cel.UnaryBinding(func(v ref.Val) ref.Val {
					u, err := url.Parse(stringOf(v))
					if err != nil {
						return types.NewStringInterfaceMap(types.DefaultTypeAdapter, map[string]any{})
					}
					user, pass := "", ""
					if u.User != nil {
						user = u.User.Username()
						pass, _ = u.User.Password()
					}
					m := map[string]any{
						"scheme":   u.Scheme,
						"host":     u.Hostname(),
						"port":     u.Port(),
						"path":     u.Path,
						"query":    u.RawQuery,
						"fragment": u.Fragment,
						"username": user,
						"password": pass,
					}
					return types.NewStringInterfaceMap(types.DefaultTypeAdapter, m)
				}),
			),
		),
	}
}

// cidrContains accepts a CIDR ("10.0.0.0/8") or a bare IP ("8.8.8.8" or "::1").
func cidrContains(s string, ip net.IP) bool {
	if !strings.Contains(s, "/") {
		if strings.Contains(s, ":") {
			s += "/128"
		} else {
			s += "/32"
		}
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return false
	}
	return n.Contains(ip)
}

func stringOf(v ref.Val) string {
	if s, ok := v.Value().(string); ok {
		return s
	}
	return ""
}
