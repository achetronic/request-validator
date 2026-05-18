// Package celenv builds the CEL environment used by request-validator
// policies, registers the custom functions catalogued in the README and
// provides a small program cache so each unique expression is compiled
// at most once.
//
// The package owns the contract between policies and Go code. The shape of
// the `request` variable exposed to CEL is the source of truth for the
// values policies can introspect.
package celenv

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
)

// Env is the compiled CEL environment plus a compiled-program cache.
type Env struct {
	env     *cel.Env
	mu      sync.RWMutex
	cache   map[string]cel.Program
}

// New builds the global CEL environment with all custom functions and
// extension libraries registered.
func New() (*Env, error) {
	e, err := cel.NewEnv(
		// Variables visible to policies.
		// - `request` carries the request being authorised.
		// - `facts`   is the snapshot of the facts registry
		//   (inline / file / url). Empty when no facts entries declared.
		cel.Variable("request", cel.DynType),
		cel.Variable("facts", cel.DynType),

		// Bundled CEL extensions we want to ship by default.
		ext.Strings(),  // s.split(sep), s.replace, s.indexOf, s.lower(), etc.
		ext.Encoders(), // base64.encode, base64.decode
		ext.Lists(),    // .sort(), .distinct(), .flatten(), .reverse()
		ext.Sets(),     // sets.contains, sets.intersects, sets.equivalent
		ext.Math(),     // math.greatest, math.least
		ext.Bindings(), // cel.bind(name, value, expr)

		// Our custom function catalogue.
		netLibrary(),
		stringLibrary(),
		encodingLibrary(),
		timeLibrary(),
		dataLibrary(),
		httpShortcutsLibrary(),
	)
	if err != nil {
		return nil, fmt.Errorf("build CEL env: %w", err)
	}
	return &Env{env: e, cache: map[string]cel.Program{}}, nil
}

// Compile turns a CEL source string into a runnable Program. Programs are
// cached by source so repeated compilations of the same expression are free.
// The CEL program must return a boolean - non-boolean results are treated as
// an evaluation error at runtime.
func (e *Env) Compile(src string) (cel.Program, error) {
	e.mu.RLock()
	if p, ok := e.cache[src]; ok {
		e.mu.RUnlock()
		return p, nil
	}
	e.mu.RUnlock()

	ast, iss := e.env.Compile(src)
	if iss.Err() != nil {
		return nil, fmt.Errorf("compile %q: %w", src, iss.Err())
	}
	if t := ast.OutputType(); t != cel.BoolType && t != cel.DynType {
		return nil, fmt.Errorf("expression must return bool, got %s for %q", t.String(), src)
	}
	prog, err := e.env.Program(ast,
		cel.EvalOptions(cel.OptOptimize),
		cel.InterruptCheckFrequency(100),
	)
	if err != nil {
		return nil, fmt.Errorf("program for %q: %w", src, err)
	}

	e.mu.Lock()
	e.cache[src] = prog
	e.mu.Unlock()
	return prog, nil
}

// Eval runs a previously compiled program with the given `request` and
// `facts` activation values. Both are passed as map<string, any> for
// flexibility - the keys must match the variables declared by the env.
// Returns the boolean result; any conversion failure surfaces as an error.
func Eval(ctx context.Context, prog cel.Program, requestVar, factsVar map[string]any) (bool, error) {
	if factsVar == nil {
		factsVar = map[string]any{}
	}
	out, _, err := prog.ContextEval(ctx, map[string]any{
		"request": requestVar,
		"facts":   factsVar,
	})
	if err != nil {
		return false, err
	}
	switch v := out.(type) {
	case types.Bool:
		return bool(v), nil
	}
	// Best-effort conversion: anything truthy/falsy via CEL's own rules.
	if b, ok := out.Value().(bool); ok {
		return b, nil
	}
	return false, fmt.Errorf("expression did not evaluate to a bool, got %T", out.Value())
}

// boolVal is a tiny helper to return a CEL bool from Go bool.
func boolVal(b bool) ref.Val { return types.Bool(b) }
