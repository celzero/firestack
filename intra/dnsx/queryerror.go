// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
package dnsx

import (
	"errors"

	x "github.com/celzero/firestack/intra/android/dnsx"
)

const (
	Start          = x.Start
	Complete       = x.Complete
	SendFailed     = x.SendFailed
	NoResponse     = x.NoResponse
	BadQuery       = x.BadQuery
	BadResponse    = x.BadResponse
	InternalError  = x.InternalError
	TransportError = x.TransportError
	ClientError    = x.ClientError
)

var noerr = errors.New("no error")

type QueryError struct {
	status int
	err    error
}

func (e *QueryError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *QueryError) Unwrap() error {
	return e.err // may be nil and that's how it should be
}

func (e *QueryError) Status() int {
	return e.status
}

func (e *QueryError) strstatus() string {
	switch e.status {
	case Start:
		return "Start"
	case Complete:
		return "Complete"
	case SendFailed:
		return "SendFailed"
	case NoResponse:
		return "NoResponse"
	case BadQuery:
		return "BadQuery"
	case BadResponse:
		return "BadResponse"
	case InternalError:
		return "InternalError"
	case TransportError:
		return "TransportError"
	case ClientError:
		return "ClientError"
	default:
		return "Unknown"
	}
}

func (e *QueryError) String() string {
	return e.strstatus() + ":" + e.Error()
}

func (e *QueryError) SendFailed() bool {
	return e.status == SendFailed
}

func newQueryError(no int, err error) *QueryError {
	return &QueryError{no, err} // err may be nil
}

func NewSendFailedQueryError(err error) *QueryError {
	return newQueryError(SendFailed, err)
}

func NewNoResponseQueryError(err error) *QueryError {
	return newQueryError(NoResponse, err)
}

func NewInternalQueryError(err error) *QueryError {
	return newQueryError(InternalError, err)
}

func NewBadQueryError(err error) *QueryError {
	return newQueryError(BadQuery, err)
}

func NewBadResponseQueryError(err error) *QueryError {
	return newQueryError(BadResponse, err)
}

// with http, for 5xx errors
func NewTransportQueryError(err error) *QueryError {
	return newQueryError(TransportError, err)
}

// with http, for 4xx errors
func NewClientQueryError(err error) *QueryError {
	return newQueryError(ClientError, err)
}
