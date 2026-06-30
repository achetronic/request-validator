// SPDX-FileCopyrightText: 2026 Alby Hernández <hola@achetronic.com>
// SPDX-License-Identifier: Apache-2.0

package celenv

import (
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// timeLibrary registers time-related functions.
//
//	now()   timestamp   Current wall-clock time in UTC.
//
// CEL already exposes type conversions and accessors on timestamps
// (getFullYear, getDayOfWeek, getHours, getMinutes, getSeconds, etc.).
func timeLibrary() cel.EnvOption {
	return cel.Lib(timeLib{})
}

type timeLib struct{}

func (timeLib) LibraryName() string                 { return "rv.time" }
func (timeLib) ProgramOptions() []cel.ProgramOption { return nil }

func (timeLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("now",
			cel.Overload("now_no_args", []*cel.Type{}, cel.TimestampType,
				cel.FunctionBinding(func(_ ...ref.Val) ref.Val {
					return types.Timestamp{Time: time.Now().UTC()}
				}),
			),
		),
	}
}
