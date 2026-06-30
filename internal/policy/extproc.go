// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"

	"request-validator/internal/celenv"
)

// ResolvedMutation represents an evaluated extProc traffic modification.
type ResolvedMutation struct {
	Op          string            // setHeader|appendHeader|removeHeader|setBody|setStatus|directResponse
	Name        string            // header ops (vacio en setBody/setStatus)
	Value       string            // setHeader/appendHeader/setBody: valor ya evaluado
	Status      int               // setStatus: codigo ya evaluado
	RespStatus  int               // directResponse: status
	RespHeaders map[string]string // directResponse: headers
	RespBody    string            // directResponse: body
	Rule        string            // "group/rule" que origino la mutacion (para logging)
	DryRun      bool              // true si la regla origen tenia dryRun:true
}

// ProcResult contains the ordered sequence of resolved mutations.
type ProcResult struct {
	Mutations []ResolvedMutation // en orden de aplicacion; vacio si nada matcheo
}

// EvaluateProc processes extProc policies and generates resolved mutations.
// It iterates matching groups and rules based on phase and evaluation mode.
func (c *Config) EvaluateProc(ctx context.Context, phase string, req *Request, resp *Response) ProcResult {
	if req == nil {
		return ProcResult{}
	}

	vars := map[string]any{
		"request": buildRequestVar(req),
		"facts":   c.snapshot(),
	}
	if (phase == "responseHeaders" || phase == "responseBody") && resp != nil {
		vars["response"] = buildResponseVar(resp)
	}

	var resolved []ResolvedMutation

	for gi := range c.Groups {
		g := &c.Groups[gi]
		if g.Parameters.Engine != "extProc" || g.Parameters.Phase != phase {
			continue
		}

		if g.matchProg != nil {
			ok, err := celenv.Eval(ctx, g.matchProg, vars)
			if err != nil || !ok {
				continue
			}
		}

		if g.Parameters.Mode == "firstMatch" {
			for ri := range g.Rules {
				r := &g.Rules[ri]
				ok, err := celenv.Eval(ctx, r.matchProg, vars)
				if err != nil {
					continue
				}
				if ok {
					resolved = append(resolved, c.resolveMutations(ctx, g, r, vars)...)
					break
				}
			}
		} else if g.Parameters.Mode == "applyAll" {
			for ri := range g.Rules {
				r := &g.Rules[ri]
				ok, err := celenv.Eval(ctx, r.matchProg, vars)
				if err != nil {
					continue
				}
				if ok {
					resolved = append(resolved, c.resolveMutations(ctx, g, r, vars)...)
				}
			}
		}
	}

	return ProcResult{
		Mutations: resolved,
	}
}

// resolveMutations evaluates each mutation expression of a matching rule.
// Non-string/non-int or failed evaluations are skipped safely (fail-safe).
func (c *Config) resolveMutations(ctx context.Context, g *Group, r *Rule, vars map[string]any) []ResolvedMutation {
	var list []ResolvedMutation
	ruleName := g.Name + "/" + r.Name

	for _, m := range r.Mutations {
		switch m.Op {
		case "directResponse":
			hdrs, err := celenv.EvalStringMap(ctx, m.headersProg, vars)
			if err != nil {
				continue
			}
			body, err := celenv.EvalString(ctx, m.bodyProg, vars)
			if err != nil {
				continue
			}
			list = append(list, ResolvedMutation{
				Op:          m.Op,
				RespStatus:  m.Status,
				RespHeaders: hdrs,
				RespBody:    body,
				Rule:        ruleName,
				DryRun:      r.DryRun,
			})
		case "setHeader", "appendHeader":
			val, err := celenv.EvalString(ctx, m.valueProg, vars)
			if err != nil {
				continue
			}
			list = append(list, ResolvedMutation{
				Op:     m.Op,
				Name:   m.Name,
				Value:  val,
				Rule:   ruleName,
				DryRun: r.DryRun,
			})
		case "setBody":
			val, err := celenv.EvalString(ctx, m.valueProg, vars)
			if err != nil {
				continue
			}
			list = append(list, ResolvedMutation{
				Op:     m.Op,
				Value:  val,
				Rule:   ruleName,
				DryRun: r.DryRun,
			})
		case "setStatus":
			code, err := celenv.EvalInt(ctx, m.codeProg, vars)
			if err != nil {
				continue
			}
			list = append(list, ResolvedMutation{
				Op:     m.Op,
				Status: int(code),
				Rule:   ruleName,
				DryRun: r.DryRun,
			})
		case "removeHeader":
			list = append(list, ResolvedMutation{
				Op:     m.Op,
				Name:   m.Name,
				Rule:   ruleName,
				DryRun: r.DryRun,
			})
		}
	}
	return list
}
