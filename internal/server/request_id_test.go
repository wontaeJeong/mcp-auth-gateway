package server

import (
	"errors"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestNewRequestIDFailsClosedWhenEntropyFails(t *testing.T) {
	requestID, err := newRequestID(failingReader{})
	if err == nil {
		t.Fatal("newRequestID() error = nil")
	}
	if requestID != "" {
		t.Fatalf("newRequestID() = %q, want empty value on failure", requestID)
	}
}
