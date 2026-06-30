// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

// Package grpcserver implements the Envoy external processing (ext_proc) gRPC server.
package grpcserver

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	epb "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"

	"request-validator/internal/log"
	"request-validator/internal/policy"
)

// Server implements the ExternalProcessorServer interface.
type Server struct {
	epb.UnimplementedExternalProcessorServer
	policy atomic.Pointer[policy.Config]
	srv    *grpc.Server
}

// New builds a server bound to the given initial policy.
func New(initial *policy.Config) *Server {
	s := &Server{}
	s.policy.Store(initial)
	return s
}

// SetPolicy atomically installs a new policy and returns the old one.
func (s *Server) SetPolicy(c *policy.Config) *policy.Config {
	return s.policy.Swap(c)
}

// Policy returns the currently installed policy.
func (s *Server) Policy() *policy.Config {
	return s.policy.Load()
}

// Run starts the TCP listener and blocks until Stop or fatal error.
func (s *Server) Run(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	s.srv = grpc.NewServer()
	epb.RegisterExternalProcessorServer(s.srv, s)

	log.Infow("starting grpc server", "addr", addr)
	err = s.srv.Serve(lis)
	if errors.Is(err, grpc.ErrServerStopped) {
		return nil
	}
	return err
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() {
	if s.srv != nil {
		s.srv.GracefulStop()
	}
}

// Process implements the bidirectional processing stream.
func (s *Server) Process(stream epb.ExternalProcessor_ProcessServer) error {
	ctx := stream.Context()
	var req *policy.Request
	var resp *policy.Response

	for {
		reqMsg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		p := s.policy.Load()
		if p == nil {
			respMsg := buildContinueResponse(reqMsg)
			if err := stream.Send(respMsg); err != nil {
				return err
			}
			continue
		}

		switch r := reqMsg.Request.(type) {
		case *epb.ProcessingRequest_RequestHeaders:
			req = parseRequestHeaders(r.RequestHeaders)
			res := p.EvaluateProc(ctx, "requestHeaders", req, nil)
			respMsg := s.handleProcResult("requestHeaders", res, p)
			if err := stream.Send(respMsg); err != nil {
				return err
			}

		case *epb.ProcessingRequest_RequestBody:
			if req == nil {
				req = &policy.Request{Headers: make(http.Header)}
			}
			bodyChunk := r.RequestBody.Body
			req.Body = append(req.Body, bodyChunk...)

			limit := p.Defaults.ExtProc.MaxBodyBytes.Int64()
			if int64(len(req.Body)) > limit {
				onBodyOverflow := p.Defaults.ExtProc.OnBodyOverflow
				log.Warnw("ext_proc body overflow",
					"phase", "requestBody",
					"limit", limit,
					"body_size", len(req.Body),
					"action", onBodyOverflow,
					"dry_run", p.Defaults.DryRun,
				)
				if onBodyOverflow == "fail" {
					if p.Defaults.DryRun {
						respMsg := &epb.ProcessingResponse{
							Response: &epb.ProcessingResponse_RequestBody{
								RequestBody: &epb.BodyResponse{
									Response: &epb.CommonResponse{
										Status: epb.CommonResponse_CONTINUE,
									},
								},
							},
						}
						if err := stream.Send(respMsg); err != nil {
							return err
						}
					} else {
						respMsg := &epb.ProcessingResponse{
							Response: &epb.ProcessingResponse_ImmediateResponse{
								ImmediateResponse: &epb.ImmediateResponse{
									Status: &typev3.HttpStatus{
										Code: typev3.StatusCode(500),
									},
									Details: "ext_proc body overflow",
								},
							},
						}
						if err := stream.Send(respMsg); err != nil {
							return err
						}
					}
				} else {
					respMsg := &epb.ProcessingResponse{
						Response: &epb.ProcessingResponse_RequestBody{
							RequestBody: &epb.BodyResponse{
								Response: &epb.CommonResponse{
									Status: epb.CommonResponse_CONTINUE,
								},
							},
						},
					}
					if err := stream.Send(respMsg); err != nil {
						return err
					}
				}
				continue
			}

			res := p.EvaluateProc(ctx, "requestBody", req, nil)
			respMsg := s.handleProcResult("requestBody", res, p)
			if err := stream.Send(respMsg); err != nil {
				return err
			}

		case *epb.ProcessingRequest_ResponseHeaders:
			if req == nil {
				req = &policy.Request{Headers: make(http.Header)}
			}
			resp = parseResponseHeaders(r.ResponseHeaders)
			res := p.EvaluateProc(ctx, "responseHeaders", req, resp)
			respMsg := s.handleProcResult("responseHeaders", res, p)
			if err := stream.Send(respMsg); err != nil {
				return err
			}

		case *epb.ProcessingRequest_ResponseBody:
			if req == nil {
				req = &policy.Request{Headers: make(http.Header)}
			}
			if resp == nil {
				resp = &policy.Response{Headers: make(http.Header)}
			}
			bodyChunk := r.ResponseBody.Body
			resp.Body = append(resp.Body, bodyChunk...)

			limit := p.Defaults.ExtProc.MaxBodyBytes.Int64()
			if int64(len(resp.Body)) > limit {
				onBodyOverflow := p.Defaults.ExtProc.OnBodyOverflow
				log.Warnw("ext_proc body overflow",
					"phase", "responseBody",
					"limit", limit,
					"body_size", len(resp.Body),
					"action", onBodyOverflow,
					"dry_run", p.Defaults.DryRun,
				)
				if onBodyOverflow == "fail" {
					if p.Defaults.DryRun {
						respMsg := &epb.ProcessingResponse{
							Response: &epb.ProcessingResponse_ResponseBody{
								ResponseBody: &epb.BodyResponse{
									Response: &epb.CommonResponse{
										Status: epb.CommonResponse_CONTINUE,
									},
								},
							},
						}
						if err := stream.Send(respMsg); err != nil {
							return err
						}
					} else {
						respMsg := &epb.ProcessingResponse{
							Response: &epb.ProcessingResponse_ImmediateResponse{
								ImmediateResponse: &epb.ImmediateResponse{
									Status: &typev3.HttpStatus{
										Code: typev3.StatusCode(500),
									},
									Details: "ext_proc body overflow",
								},
							},
						}
						if err := stream.Send(respMsg); err != nil {
							return err
						}
					}
				} else {
					respMsg := &epb.ProcessingResponse{
						Response: &epb.ProcessingResponse_ResponseBody{
							ResponseBody: &epb.BodyResponse{
								Response: &epb.CommonResponse{
									Status: epb.CommonResponse_CONTINUE,
								},
							},
						},
					}
					if err := stream.Send(respMsg); err != nil {
						return err
					}
				}
				continue
			}

			res := p.EvaluateProc(ctx, "responseBody", req, resp)
			respMsg := s.handleProcResult("responseBody", res, p)
			if err := stream.Send(respMsg); err != nil {
				return err
			}

		default:
			respMsg := buildContinueResponse(reqMsg)
			if err := stream.Send(respMsg); err != nil {
				return err
			}
		}
	}
}

// handleProcResult filters shadow mutations and logs/builds the processing response.
func (s *Server) handleProcResult(phase string, res policy.ProcResult, p *policy.Config) *epb.ProcessingResponse {
	dryGlobal := p.Defaults.DryRun

	// 1. CORTOCIRCUITO: check for first applied directResponse
	for _, m := range res.Mutations {
		effectiveDry := dryGlobal || m.DryRun
		if m.Op == "directResponse" && !effectiveDry {
			log.Infow("extProc phase evaluated",
				"engine", "extProc",
				"phase", phase,
				"direct_response", fmt.Sprintf("%s:%d", m.Rule, m.RespStatus),
				"dry_run", false,
			)

			return &epb.ProcessingResponse{
				Response: &epb.ProcessingResponse_ImmediateResponse{
					ImmediateResponse: &epb.ImmediateResponse{
						Status: &typev3.HttpStatus{
							Code: typev3.StatusCode(m.RespStatus),
						},
						Headers: buildHeaderMutationFromMap(m.RespHeaders),
						Body:    []byte(m.RespBody),
					},
				},
			}
		}
	}

	var applied []policy.ResolvedMutation
	var appliedLog []string
	var shadowLog []string

	for _, m := range res.Mutations {
		effectiveDry := dryGlobal || m.DryRun
		if effectiveDry {
			switch m.Op {
			case "setHeader", "appendHeader":
				shadowLog = append(shadowLog, fmt.Sprintf("%s:%s(%s=%s)", m.Rule, m.Op, m.Name, m.Value))
			case "removeHeader":
				shadowLog = append(shadowLog, fmt.Sprintf("%s:%s(%s)", m.Rule, m.Op, m.Name))
			case "setBody":
				shadowLog = append(shadowLog, fmt.Sprintf("%s:%s(len=%d)", m.Rule, m.Op, len(m.Value)))
			case "setStatus":
				shadowLog = append(shadowLog, fmt.Sprintf("%s:%s(%d)", m.Rule, m.Op, m.Status))
			case "directResponse":
				shadowLog = append(shadowLog, fmt.Sprintf("%s:would directRespond(%d)", m.Rule, m.RespStatus))
			}
		} else {
			if m.Op == "directResponse" {
				continue
			}
			applied = append(applied, m)
			switch m.Op {
			case "setHeader", "appendHeader":
				appliedLog = append(appliedLog, fmt.Sprintf("%s:%s(%s=%s)", m.Rule, m.Op, m.Name, m.Value))
			case "removeHeader":
				appliedLog = append(appliedLog, fmt.Sprintf("%s:%s(%s)", m.Rule, m.Op, m.Name))
			case "setBody":
				appliedLog = append(appliedLog, fmt.Sprintf("%s:%s(len=%d)", m.Rule, m.Op, len(m.Value)))
			case "setStatus":
				appliedLog = append(appliedLog, fmt.Sprintf("%s:%s(%d)", m.Rule, m.Op, m.Status))
			}
		}
	}

	// Only the no-op case (nothing applied, nothing shadowed) is logged at
	// DEBUG: at INFO it floods, since extProc runs on every request/phase.
	logProc := log.Infow
	if len(appliedLog) == 0 && len(shadowLog) == 0 {
		logProc = log.Debugw
	}
	logProc("extProc phase evaluated",
		"engine", "extProc",
		"phase", phase,
		"applied", appliedLog,
		"shadow", shadowLog,
		"dry_run", dryGlobal,
	)

	hm, bm := buildMutations(applied)
	common := &epb.CommonResponse{
		Status:         epb.CommonResponse_CONTINUE,
		HeaderMutation: hm,
		BodyMutation:   bm,
	}

	switch phase {
	case "requestHeaders":
		return &epb.ProcessingResponse{
			Response: &epb.ProcessingResponse_RequestHeaders{
				RequestHeaders: &epb.HeadersResponse{
					Response: common,
				},
			},
		}
	case "requestBody":
		return &epb.ProcessingResponse{
			Response: &epb.ProcessingResponse_RequestBody{
				RequestBody: &epb.BodyResponse{
					Response: common,
				},
			},
		}
	case "responseHeaders":
		return &epb.ProcessingResponse{
			Response: &epb.ProcessingResponse_ResponseHeaders{
				ResponseHeaders: &epb.HeadersResponse{
					Response: common,
				},
			},
		}
	case "responseBody":
		return &epb.ProcessingResponse{
			Response: &epb.ProcessingResponse_ResponseBody{
				ResponseBody: &epb.BodyResponse{
					Response: common,
				},
			},
		}
	default:
		return &epb.ProcessingResponse{
			Response: &epb.ProcessingResponse_RequestHeaders{
				RequestHeaders: &epb.HeadersResponse{
					Response: common,
				},
			},
		}
	}
}

// buildHeaderMutationFromMap helper builds HeaderMutation from map deterministically.
func buildHeaderMutationFromMap(headers map[string]string) *epb.HeaderMutation {
	if len(headers) == 0 {
		return nil
	}
	var setHeaders []*corev3.HeaderValueOption
	var keys []string
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		setHeaders = append(setHeaders, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:      k,
				RawValue: []byte(headers[k]),
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	return &epb.HeaderMutation{
		SetHeaders: setHeaders,
	}
}

// buildMutations translates a list of resolved mutations to Envoy types.
func buildMutations(mutations []policy.ResolvedMutation) (*epb.HeaderMutation, *epb.BodyMutation) {
	var setHeaders []*corev3.HeaderValueOption
	var removeHeaders []string
	var bodyMutation *epb.BodyMutation

	for _, m := range mutations {
		switch m.Op {
		case "setHeader":
			setHeaders = append(setHeaders, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:      m.Name,
					RawValue: []byte(m.Value),
				},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			})
		case "appendHeader":
			setHeaders = append(setHeaders, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:      m.Name,
					RawValue: []byte(m.Value),
				},
				AppendAction: corev3.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD,
			})
		case "removeHeader":
			removeHeaders = append(removeHeaders, m.Name)
		case "setBody":
			bodyBytes := []byte(m.Value)
			bodyMutation = &epb.BodyMutation{
				Mutation: &epb.BodyMutation_Body{
					Body: bodyBytes,
				},
			}
			setHeaders = append(setHeaders, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:      "content-length",
					RawValue: []byte(strconv.Itoa(len(bodyBytes))),
				},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			})
		case "setStatus":
			setHeaders = append(setHeaders, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:      ":status",
					RawValue: []byte(strconv.Itoa(m.Status)),
				},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			})
		}
	}

	var hm *epb.HeaderMutation
	if len(setHeaders) > 0 || len(removeHeaders) > 0 {
		hm = &epb.HeaderMutation{
			SetHeaders:    setHeaders,
			RemoveHeaders: removeHeaders,
		}
	}

	return hm, bodyMutation
}

// buildContinueResponse returns an empty CONTINUE response matched to the request phase.
func buildContinueResponse(reqMsg *epb.ProcessingRequest) *epb.ProcessingResponse {
	common := &epb.CommonResponse{
		Status: epb.CommonResponse_CONTINUE,
	}

	switch reqMsg.Request.(type) {
	case *epb.ProcessingRequest_RequestHeaders:
		return &epb.ProcessingResponse{
			Response: &epb.ProcessingResponse_RequestHeaders{
				RequestHeaders: &epb.HeadersResponse{
					Response: common,
				},
			},
		}
	case *epb.ProcessingRequest_RequestBody:
		return &epb.ProcessingResponse{
			Response: &epb.ProcessingResponse_RequestBody{
				RequestBody: &epb.BodyResponse{
					Response: common,
				},
			},
		}
	case *epb.ProcessingRequest_ResponseHeaders:
		return &epb.ProcessingResponse{
			Response: &epb.ProcessingResponse_ResponseHeaders{
				ResponseHeaders: &epb.HeadersResponse{
					Response: common,
				},
			},
		}
	case *epb.ProcessingRequest_ResponseBody:
		return &epb.ProcessingResponse{
			Response: &epb.ProcessingResponse_ResponseBody{
				ResponseBody: &epb.BodyResponse{
					Response: common,
				},
			},
		}
	default:
		return &epb.ProcessingResponse{
			Response: &epb.ProcessingResponse_RequestHeaders{
				RequestHeaders: &epb.HeadersResponse{
					Response: common,
				},
			},
		}
	}
}

func parseRequestHeaders(h *epb.HttpHeaders) *policy.Request {
	var method, scheme, authority, pathAndQuery string
	reqHeaders := make(http.Header)
	if h != nil && h.Headers != nil {
		for _, hv := range h.Headers.Headers {
			val := hv.Value
			if val == "" && len(hv.RawValue) > 0 {
				val = string(hv.RawValue)
			}
			key := strings.ToLower(hv.Key)
			switch key {
			case ":method":
				method = val
			case ":scheme":
				scheme = val
			case ":authority":
				authority = val
			case ":path":
				pathAndQuery = val
			default:
				reqHeaders.Add(hv.Key, val)
			}
		}
	}

	host := authority
	if host == "" {
		host = reqHeaders.Get("Host")
	}

	var path, rawQuery string
	if pathAndQuery != "" {
		if idx := strings.IndexByte(pathAndQuery, '?'); idx >= 0 {
			path = pathAndQuery[:idx]
			rawQuery = pathAndQuery[idx+1:]
		} else {
			path = pathAndQuery
		}
	}

	return &policy.Request{
		Method:   method,
		Scheme:   scheme,
		Host:     host,
		Path:     path,
		RawQuery: rawQuery,
		RemoteIP: extractClientIP(reqHeaders),
		Headers:  reqHeaders,
	}
}

func parseResponseHeaders(h *epb.HttpHeaders) *policy.Response {
	var statusStr string
	respHeaders := make(http.Header)
	if h != nil && h.Headers != nil {
		for _, hv := range h.Headers.Headers {
			val := hv.Value
			if val == "" && len(hv.RawValue) > 0 {
				val = string(hv.RawValue)
			}
			key := strings.ToLower(hv.Key)
			if key == ":status" {
				statusStr = val
			} else {
				respHeaders.Add(hv.Key, val)
			}
		}
	}

	status := 200
	if statusStr != "" {
		if code, err := strconv.Atoi(statusStr); err == nil {
			status = code
		}
	}

	return &policy.Response{
		Status:  status,
		Headers: respHeaders,
	}
}

func extractClientIP(h http.Header) string {
	if xff := h.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := h.Get("X-Real-Ip"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return ""
}
