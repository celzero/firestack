// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package core

import (
	"errors"
	"strings"
)

func OneErr(errs ...error) error {
	// or: cmp.Or(errs...)
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func JoinErr(errs ...error) error {
	return joinErr(false /*uniq*/, errs...)
}

func UniqErr(errs ...error) error {
	return joinErr(true /*uniq*/, errs...)
}

// must always return the interface "error" and not
// a *errMult, as client code checks for err == nil
// for a nil *errMult returned from here is always false.
// ie, if *errMult was the return type, then the "error"
// interface returned by JoinErr and UniqErr is not "nil"
// even if *errMult returned by joinErr was "nil".
// see also: IsNil() and IsNotNil()
func joinErr(uniq bool, errs ...error) error {
	if len(errs) <= 0 {
		return nil
	}

	var all []error
	var m map[error]struct{}

	if false { // unjoin?
		for _, err := range errs {
			if err == nil {
				continue
			}
			var merr *errMult
			if errors.As(err, &merr) {
				all = append(all, merr.Unwrap()...)
			}
		}
	}

	if uniq {
		m = make(map[error]struct{}, len(errs))
	}
	for _, err := range errs {
		if err == nil {
			continue
		}
		haserr := false
		if m != nil { // uniq
			if _, haserr = m[err]; !haserr {
				for k := range m {
					if haserr = errors.Is(k, err); haserr {
						break
					}
				}
			}
			m[err] = struct{}{}
		}
		if !haserr {
			all = append(all, err)
		}
	}
	if len(all) <= 0 {
		return nil
	}

	return &errMult{errs: all, sep: " | "}
}

type errMult struct {
	errs []error
	sep  string
}

func (e *errMult) Error() string {
	if e == nil {
		return "{nil}"
	}
	if len(e.errs) <= 0 {
		return "<nil>"
	} else if len(e.errs) == 1 {
		return e.errs[0].Error()
	}

	b := strings.Builder{}
	for i, err := range e.errs {
		if i != 0 { // except for first entry, add separator
			_, _ = b.WriteString(e.sep)
		}
		_, _ = b.WriteString(err.Error())
	}
	return b.String()
}

func (e *errMult) Unwrap() []error {
	if e == nil {
		return nil
	}
	return e.errs
}
