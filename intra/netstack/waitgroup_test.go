package netstack

import (
	"os"
	"sync"
	"testing"
	"time"
)

// TestWaitGroupRaceCondition tests that the WaitGroup reuse issue is fixed.
// This test reproduces the scenario where an endpoint is swapped while 
// another goroutine is waiting on the old endpoint.
func TestWaitGroupRaceCondition(t *testing.T) {
	// Create a temp file to simulate a TUN device
	tmpFile, err := os.CreateTemp("", "test_tun")
	if err != nil {
		t.Skip("Cannot create temp file for test")
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	fd := int(tmpFile.Fd())
	
	// Create a magiclink endpoint
	endpoint, err := NewEndpoint(fd, 1500, &testSink{})
	if err != nil {
		t.Fatalf("Failed to create endpoint: %v", err)
	}
	defer endpoint.Dispose()

	magicLink, ok := endpoint.(*magiclink)
	if !ok {
		t.Fatalf("Expected magiclink, got %T", endpoint)
	}

	// Start multiple goroutines that will call Wait() on the endpoint
	// while we swap endpoints in the background
	var wg sync.WaitGroup
	errors := make(chan error, 10)
	
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					errors <- r.(error)
				}
			}()
			
			// Call Wait() multiple times to increase chance of race condition
			for j := 0; j < 10; j++ {
				magicLink.Wait()
				time.Sleep(time.Millisecond)
			}
		}(i)
	}
	
	// Swap endpoints multiple times while Wait() is being called
	go func() {
		for i := 0; i < 5; i++ {
			// Create another temp file for swapping
			tmpFile2, err := os.CreateTemp("", "test_tun2")
			if err != nil {
				continue
			}
			fd2 := int(tmpFile2.Fd())
			
			// Swap to new fd
			magicLink.Swap(fd2, 1500)
			time.Sleep(time.Millisecond * 5)
			
			tmpFile2.Close()
			os.Remove(tmpFile2.Name())
		}
	}()
	
	// Wait for all goroutines to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		// Check if any errors occurred
		select {
		case err := <-errors:
			t.Fatalf("WaitGroup reuse panic occurred: %v", err)
		default:
			// Success - no panic occurred
		}
	case <-time.After(time.Second * 10):
		t.Fatal("Test timed out")
	}
}

// TestStackTraceScenario tests the specific scenario from the original stack trace
// where magiclink.Wait() is called during endpoint swapping.
func TestStackTraceScenario(t *testing.T) {
	// Create a temp file to simulate a TUN device
	tmpFile, err := os.CreateTemp("", "test_tun")
	if err != nil {
		t.Skip("Cannot create temp file for test")
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	fd := int(tmpFile.Fd())
	
	// Create a magiclink endpoint
	endpoint, err := NewEndpoint(fd, 1500, &testSink{})
	if err != nil {
		t.Fatalf("Failed to create endpoint: %v", err)
	}
	defer endpoint.Dispose()

	magicLink, ok := endpoint.(*magiclink)
	if !ok {
		t.Fatalf("Expected magiclink, got %T", endpoint)
	}

	// Simulate the exact scenario from the stack trace:
	// seamless.go:312>fdbased.go:413 - magiclink.Wait() calls endpoint.Wait()
	panicked := false
	done := make(chan struct{})
	
	// Start a goroutine that continuously calls Wait() like the tunnel waiter
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
			close(done)
		}()
		
		for i := 0; i < 100; i++ {
			magicLink.Wait()
			time.Sleep(time.Millisecond)
		}
	}()
	
	// Concurrently perform rapid endpoint swaps
	for i := 0; i < 10; i++ {
		tmpFile2, err := os.CreateTemp("", "test_tun2")
		if err != nil {
			continue
		}
		fd2 := int(tmpFile2.Fd())
		
		// Rapid swap - this should not cause WaitGroup reuse panic
		magicLink.Swap(fd2, 1500)
		
		tmpFile2.Close()
		os.Remove(tmpFile2.Name())
		time.Sleep(time.Millisecond * 2)
	}
	
	// Wait for the wait goroutine to complete
	select {
	case <-done:
		if panicked {
			t.Fatal("WaitGroup reuse panic occurred in stack trace scenario")
		}
	case <-time.After(time.Second * 15):
		t.Fatal("Test timed out")
	}
}

// testSink is a simple implementation of io.WriteCloser for testing
type testSink struct{}

func (ts *testSink) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (ts *testSink) Close() error {
	return nil
}