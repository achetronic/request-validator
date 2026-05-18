package httpserver

import (
	"log/slog"
	"net/url"
	"strings"

	"request-validator/internal/policy"
)

// accessLogAttrs builds the slog group describing a single request. The
// caller adds higher-level fields (decision, rule, reason, dryRun, duration)
// around it; this function is concerned only with what came in.
//
// Header keys are always lowercase. Excluded headers are dropped, redacted
// headers have their values masked. The body is included only when
// logging.LogBody is true; the body size is included always.
func accessLogAttrs(req *policy.Request, lg policy.Logging) slog.Attr {
	exclude := lowerSet(lg.ExcludeHeaders)
	redact := lowerSet(lg.RedactHeaders)

	hdrs := make([]any, 0, len(req.Headers)*2)
	for k, vs := range req.Headers {
		lk := strings.ToLower(k)
		if exclude[lk] {
			continue
		}
		joined := strings.Join(vs, ", ")
		if redact[lk] {
			joined = mask(joined, lg.RedactReveal)
		}
		hdrs = append(hdrs, slog.String(lk, joined))
	}

	q := redactedQuery(req.RawQuery, lg)

	body := slog.Group("body",
		slog.Int("size", len(req.Body)),
		slog.String("content_type", strings.ToLower(req.Headers.Get("Content-Type"))),
	)
	if lg.LogBody && len(req.Body) > 0 {
		body = slog.Group("body",
			slog.Int("size", len(req.Body)),
			slog.String("content_type", strings.ToLower(req.Headers.Get("Content-Type"))),
			slog.String("raw", string(req.Body)),
		)
	}

	return slog.Group("request",
		slog.String("method", req.Method),
		slog.String("scheme", req.Scheme),
		slog.String("host", req.Host),
		slog.String("path", req.Path),
		slog.String("query", q),
		slog.String("remote_ip", req.RemoteIP),
		slog.Group("headers", hdrs...),
		body,
	)
}

// lowerSet builds a lowercase string set out of a slice. Empty entries are
// ignored.
func lowerSet(xs []string) map[string]bool {
	out := make(map[string]bool, len(xs))
	for _, x := range xs {
		x = strings.TrimSpace(strings.ToLower(x))
		if x != "" {
			out[x] = true
		}
	}
	return out
}

// mask reveals the first n characters and replaces the rest with '*'. If the
// value is short enough that revealing n characters would leak most of it,
// the whole value is masked. The threshold is `2*n` so that "Bearer xyz"
// (10 chars) with n=6 still gets fully masked while a JWT (>12 chars) keeps
// its visible prefix.
func mask(v string, n int) string {
	if v == "" {
		return ""
	}
	if n <= 0 || len(v) < 2*n {
		return strings.Repeat("*", len(v))
	}
	return v[:n] + strings.Repeat("*", len(v)-n)
}

// redactedQuery returns the raw query string with the values of any
// configured-as-sensitive parameters replaced with '***'. We rebuild the
// query rather than url-encoding the parsed form so the log shows what the
// client actually sent.
func redactedQuery(raw string, lg policy.Logging) string {
	if raw == "" {
		return ""
	}
	sensitive := lowerSet(lg.RedactQueryParams)
	if len(sensitive) == 0 {
		return raw
	}
	pairs := strings.Split(raw, "&")
	for i, p := range pairs {
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			continue
		}
		name, _ := url.QueryUnescape(p[:eq])
		if sensitive[strings.ToLower(name)] {
			pairs[i] = p[:eq+1] + "***"
		}
	}
	return strings.Join(pairs, "&")
}
