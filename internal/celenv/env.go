// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

// Package celenv builds the CEL environment used by request-validator
// policies, registers the custom functions and provides a program cache.
package celenv

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
)

// Scope defines the variable visibility scope for CEL compilation.
type Scope int

const (
	// ScopeRequest permits access to request and facts.
	ScopeRequest Scope = iota
	// ScopeResponse permits access to request, response, and facts.
	ScopeResponse
)

// Env wraps the request and response CEL environments and a program cache.
type Env struct {
	requestEnv  *cel.Env
	responseEnv *cel.Env
	mu          sync.RWMutex
	cache       map[cacheKey]cel.Program
}

type cacheKey struct {
	scope Scope
	kind  string
	src   string
}

// New builds the CEL environments with all custom functions and extensions.
func New() (*Env, error) {
	commonOpts := []cel.EnvOption{
		ext.Strings(),
		ext.Encoders(),
		ext.Lists(),
		ext.Sets(),
		ext.Math(),
		ext.Bindings(),

		netLibrary(),
		stringLibrary(),
		encodingLibrary(),
		timeLibrary(),
		dataLibrary(),
		httpShortcutsLibrary(),
	}

	reqOpts := append([]cel.EnvOption{
		cel.Variable("request", cel.DynType),
		cel.Variable("facts", cel.DynType),
	}, commonOpts...)

	reqEnv, err := cel.NewEnv(reqOpts...)
	if err != nil {
		return nil, fmt.Errorf("build CEL request env: %w", err)
	}

	respOpts := append([]cel.EnvOption{
		cel.Variable("request", cel.DynType),
		cel.Variable("response", cel.DynType),
		cel.Variable("facts", cel.DynType),
	}, commonOpts...)

	respEnv, err := cel.NewEnv(respOpts...)
	if err != nil {
		return nil, fmt.Errorf("build CEL response env: %w", err)
	}

	return &Env{
		requestEnv:  reqEnv,
		responseEnv: respEnv,
		cache:       map[cacheKey]cel.Program{},
	}, nil
}

func (e *Env) envForScope(scope Scope) (*cel.Env, error) {
	switch scope {
	case ScopeRequest:
		return e.requestEnv, nil
	case ScopeResponse:
		return e.responseEnv, nil
	default:
		return nil, fmt.Errorf("unknown scope: %v", scope)
	}
}

func (e *Env) compile(src string, scope Scope, kind string, expectedType *cel.Type) (cel.Program, error) {
	key := cacheKey{scope: scope, kind: kind, src: src}
	e.mu.RLock()
	if p, ok := e.cache[key]; ok {
		e.mu.RUnlock()
		return p, nil
	}
	e.mu.RUnlock()

	cenv, err := e.envForScope(scope)
	if err != nil {
		return nil, err
	}

	ast, iss := cenv.Compile(src)
	if iss.Err() != nil {
		return nil, fmt.Errorf("compile %q in scope %v: %w", src, scope, iss.Err())
	}
	if t := ast.OutputType(); t != expectedType && !t.IsExactType(expectedType) && t != cel.DynType {
		return nil, fmt.Errorf("expression must return %s, got %s for %q", expectedType.String(), t.String(), src)
	}
	prog, err := cenv.Program(ast,
		cel.EvalOptions(cel.OptOptimize),
		cel.InterruptCheckFrequency(100),
	)
	if err != nil {
		return nil, fmt.Errorf("program for %q: %w", src, err)
	}

	e.mu.Lock()
	e.cache[key] = prog
	e.mu.Unlock()
	return prog, nil
}

// Compile compiles a CEL source expecting a boolean result.
func (e *Env) Compile(src string, scope Scope) (cel.Program, error) {
	return e.compile(src, scope, "bool", cel.BoolType)
}

// CompileString compiles a CEL source expecting a string result.
func (e *Env) CompileString(src string, scope Scope) (cel.Program, error) {
	return e.compile(src, scope, "string", cel.StringType)
}

// CompileInt compiles a CEL source expecting an integer result.
func (e *Env) CompileInt(src string, scope Scope) (cel.Program, error) {
	return e.compile(src, scope, "int", cel.IntType)
}

// CompileStringMap compiles a CEL source expecting a map[string]string result.
func (e *Env) CompileStringMap(src string, scope Scope) (cel.Program, error) {
	return e.compile(src, scope, "stringmap", cel.MapType(cel.StringType, cel.StringType))
}

// Eval runs a program with vars, expecting a boolean result.
func Eval(ctx context.Context, prog cel.Program, vars map[string]any) (bool, error) {
	if vars == nil {
		vars = map[string]any{}
	}
	out, _, err := prog.ContextEval(ctx, vars)
	if err != nil {
		return false, err
	}
	switch v := out.(type) {
	case types.Bool:
		return bool(v), nil
	}
	if b, ok := out.Value().(bool); ok {
		return b, nil
	}
	return false, fmt.Errorf("expression did not evaluate to a bool, got %T", out.Value())
}

// EvalString runs a program with vars, expecting a string result.
func EvalString(ctx context.Context, prog cel.Program, vars map[string]any) (string, error) {
	if vars == nil {
		vars = map[string]any{}
	}
	out, _, err := prog.ContextEval(ctx, vars)
	if err != nil {
		return "", err
	}
	switch v := out.(type) {
	case types.String:
		return string(v), nil
	}
	if s, ok := out.Value().(string); ok {
		return s, nil
	}
	return "", fmt.Errorf("expression did not evaluate to a string, got %T", out.Value())
}

// EvalInt runs a program with vars, expecting an integer result.
func EvalInt(ctx context.Context, prog cel.Program, vars map[string]any) (int64, error) {
	if vars == nil {
		vars = map[string]any{}
	}
	out, _, err := prog.ContextEval(ctx, vars)
	if err != nil {
		return 0, err
	}
	switch v := out.(type) {
	case types.Int:
		return int64(v), nil
	}
	switch val := out.Value().(type) {
	case int64:
		return val, nil
	case int:
		return int64(val), nil
	case int32:
		return int64(val), nil
	}
	return 0, fmt.Errorf("expression did not evaluate to an int, got %T", out.Value())
}

// EvalStringMap runs a program with vars, expecting a map[string]string result.
func EvalStringMap(ctx context.Context, prog cel.Program, vars map[string]any) (map[string]string, error) {
	if vars == nil {
		vars = map[string]any{}
	}
	out, _, err := prog.ContextEval(ctx, vars)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("expression evaluated to nil")
	}
	val := out.Value()
	if val == nil {
		return nil, fmt.Errorf("expression evaluated to a nil value")
	}

	rv := reflect.ValueOf(val)
	if rv.Kind() != reflect.Map {
		return nil, fmt.Errorf("expression did not evaluate to a map, got %T", val)
	}

	res := make(map[string]string, rv.Len())
	iter := rv.MapRange()
	for iter.Next() {
		k := iter.Key().Interface()
		v := iter.Value().Interface()

		// Unwrap ref.Val if needed
		if refK, ok := k.(ref.Val); ok {
			k = refK.Value()
		}
		if refV, ok := v.(ref.Val); ok {
			v = refV.Value()
		}

		kStr, ok := k.(string)
		if !ok {
			return nil, fmt.Errorf("directResponse headers must be map<string,string>, key is not a string (got %T)", k)
		}

		vStr, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("directResponse headers must be map<string,string>, value for key %q is %T", kStr, v)
		}

		res[kStr] = vStr
	}
	return res, nil
}

// boolVal is a tiny helper to return a CEL bool from Go bool.
func boolVal(b bool) ref.Val { return types.Bool(b) }
