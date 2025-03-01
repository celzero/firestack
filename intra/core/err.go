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

func joinErr(uniq bool, errs ...error) error {
	var all []error
	var m map[error]struct{}

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
	if len(all) == 1 {
		return all[0]
	}

	return &errMult{errs: all, sep: " | "}
}

type errMult struct {
	errs []error
	sep  string
}

func (e *errMult) Error() string {
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
	return e.errs
}
