package smb2

import (
	"context"
	"encoding/binary"
	"testing"

	. "github.com/hirochachacha/go-smb2/internal/erref"
	. "github.com/hirochachacha/go-smb2/internal/smb2"
)

func syntheticResponse(status uint32, flags uint32, messageID uint64, asyncID uint64, sessionID uint64) []byte {
	pkt := make([]byte, 64)
	copy(pkt[:4], []byte(MAGIC))
	binary.LittleEndian.PutUint16(pkt[4:6], 64)
	binary.LittleEndian.PutUint32(pkt[8:12], status)
	binary.LittleEndian.PutUint16(pkt[12:14], SMB2_IOCTL)
	binary.LittleEndian.PutUint32(pkt[16:20], flags)
	binary.LittleEndian.PutUint64(pkt[24:32], messageID)
	if flags&SMB2_FLAGS_ASYNC_COMMAND != 0 {
		binary.LittleEndian.PutUint64(pkt[32:40], asyncID)
	}
	binary.LittleEndian.PutUint64(pkt[40:48], sessionID)
	return pkt
}

func TestTryVerifyAllowsUnsignedAsyncInterim(t *testing.T) {
	const sessionID = 42
	conn := &conn{
		requireSigning: true,
		session:        &session{sessionId: sessionID},
	}
	pkt := syntheticResponse(uint32(STATUS_PENDING), SMB2_FLAGS_SERVER_TO_REDIR|SMB2_FLAGS_ASYNC_COMMAND, 7, 9, sessionID)
	if err := conn.tryVerify(pkt, false); err != nil {
		t.Fatalf("unsigned async interim response rejected: %v", err)
	}
}

func TestTryVerifyStillRequiresSignedNonInterim(t *testing.T) {
	const sessionID = 42
	conn := &conn{
		requireSigning: true,
		session:        &session{sessionId: sessionID},
	}
	tests := []struct {
		name  string
		flags uint32
	}{
		{name: "synchronous pending", flags: SMB2_FLAGS_SERVER_TO_REDIR},
		{name: "asynchronous success", flags: SMB2_FLAGS_SERVER_TO_REDIR | SMB2_FLAGS_ASYNC_COMMAND},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := uint32(STATUS_PENDING)
			if tt.name == "asynchronous success" {
				status = uint32(STATUS_SUCCESS)
			}
			pkt := syntheticResponse(status, tt.flags, 7, 9, sessionID)
			if err := conn.tryVerify(pkt, false); err == nil {
				t.Fatal("unsigned non-interim response was accepted")
			}
		})
	}
}

func TestTryHandleAsyncPendingThenFinal(t *testing.T) {
	const messageID = 7
	const asyncID = 9
	conn := &conn{
		account:             openAccount(16),
		outstandingRequests: newOutstandingRequests(),
	}
	rr := &requestResponse{
		msgId:         messageID,
		creditRequest: 1,
		recv:          make(chan []byte, 1),
	}
	conn.outstandingRequests.set(messageID, rr)

	pending := syntheticResponse(uint32(STATUS_PENDING), SMB2_FLAGS_SERVER_TO_REDIR|SMB2_FLAGS_ASYNC_COMMAND, messageID, asyncID, 42)
	if err := conn.tryHandle(pending, nil); err != nil {
		t.Fatalf("pending response rejected: %v", err)
	}
	if rr.asyncId != asyncID {
		t.Fatalf("async id = %d, want %d", rr.asyncId, asyncID)
	}
	if _, ok := conn.outstandingRequests.requests[messageID]; !ok {
		t.Fatal("pending response removed the outstanding request")
	}

	final := syntheticResponse(uint32(STATUS_SUCCESS), SMB2_FLAGS_SERVER_TO_REDIR|SMB2_FLAGS_ASYNC_COMMAND, messageID, asyncID, 42)
	if err := conn.tryHandle(final, nil); err != nil {
		t.Fatalf("final response rejected: %v", err)
	}
	if _, ok := conn.outstandingRequests.requests[messageID]; ok {
		t.Fatal("final response left the outstanding request installed")
	}
	if got := <-rr.recv; string(got) != string(final) {
		t.Fatal("final response was not delivered")
	}
}

func TestTryHandleSynchronousTerminalResponse(t *testing.T) {
	const messageID = 7
	conn := &conn{account: openAccount(16), outstandingRequests: newOutstandingRequests()}
	rr := &requestResponse{msgId: messageID, creditRequest: 1, recv: make(chan []byte, 1)}
	conn.outstandingRequests.set(messageID, rr)

	response := syntheticResponse(uint32(STATUS_SUCCESS), SMB2_FLAGS_SERVER_TO_REDIR, messageID, 0, 42)
	if err := conn.tryHandle(response, nil); err != nil {
		t.Fatalf("synchronous response rejected: %v", err)
	}
	if got := <-rr.recv; string(got) != string(response) {
		t.Fatal("synchronous response was not delivered")
	}
}

func TestTryHandleAsyncTerminalFailureAfterPending(t *testing.T) {
	const messageID = 7
	const asyncID = 9
	conn := &conn{account: openAccount(16), outstandingRequests: newOutstandingRequests()}
	rr := &requestResponse{msgId: messageID, creditRequest: 1, recv: make(chan []byte, 1)}
	conn.outstandingRequests.set(messageID, rr)

	pending := syntheticResponse(uint32(STATUS_PENDING), SMB2_FLAGS_SERVER_TO_REDIR|SMB2_FLAGS_ASYNC_COMMAND, messageID, asyncID, 42)
	if err := conn.tryHandle(pending, nil); err != nil {
		t.Fatalf("pending response rejected: %v", err)
	}
	final := syntheticResponse(uint32(STATUS_ACCESS_DENIED), SMB2_FLAGS_SERVER_TO_REDIR|SMB2_FLAGS_ASYNC_COMMAND, messageID, asyncID, 42)
	if err := conn.tryHandle(final, nil); err != nil {
		t.Fatalf("terminal failure response rejected: %v", err)
	}
	if got := <-rr.recv; string(got) != string(final) {
		t.Fatal("terminal failure response was not delivered")
	}
}

func TestTryHandleRejectsUnexpectedAndDuplicateAsyncCompletion(t *testing.T) {
	c := &conn{account: openAccount(16), outstandingRequests: newOutstandingRequests()}
	unexpected := syntheticResponse(uint32(STATUS_SUCCESS), SMB2_FLAGS_SERVER_TO_REDIR|SMB2_FLAGS_ASYNC_COMMAND, 7, 9, 42)
	rr := &requestResponse{msgId: 7, creditRequest: 1, recv: make(chan []byte, 1)}
	c.outstandingRequests.set(7, rr)
	if err := c.tryHandle(unexpected, nil); err == nil {
		t.Fatal("unexpected async completion was accepted")
	}

	c = &conn{account: openAccount(16), outstandingRequests: newOutstandingRequests()}
	rr = &requestResponse{msgId: 7, creditRequest: 1, recv: make(chan []byte, 1)}
	c.outstandingRequests.set(7, rr)
	final := syntheticResponse(uint32(STATUS_SUCCESS), SMB2_FLAGS_SERVER_TO_REDIR, 7, 0, 42)
	if err := c.tryHandle(final, nil); err != nil {
		t.Fatalf("terminal response rejected: %v", err)
	}
	if err := c.tryHandle(final, nil); err == nil {
		t.Fatal("duplicate terminal response was accepted")
	}
}

func TestConnRecvCancellationRemovesOutstandingRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn := &conn{outstandingRequests: newOutstandingRequests()}
	rr := &requestResponse{msgId: 7, ctx: ctx, recv: make(chan []byte, 1)}
	conn.outstandingRequests.set(rr.msgId, rr)
	if _, err := conn.recv(rr); err == nil {
		t.Fatal("canceled request returned without an error")
	}
	if _, ok := conn.outstandingRequests.requests[rr.msgId]; ok {
		t.Fatal("canceled request remained outstanding")
	}
}

func TestTryHandleRejectsInvalidAsyncCorrelation(t *testing.T) {
	tests := []struct {
		name       string
		pending    []byte
		completion []byte
	}{
		{
			name:       "pending without async header",
			pending:    syntheticResponse(uint32(STATUS_PENDING), SMB2_FLAGS_SERVER_TO_REDIR, 7, 0, 42),
			completion: nil,
		},
		{
			name:       "pending with zero async id",
			pending:    syntheticResponse(uint32(STATUS_PENDING), SMB2_FLAGS_SERVER_TO_REDIR|SMB2_FLAGS_ASYNC_COMMAND, 7, 0, 42),
			completion: nil,
		},
		{
			name:       "final with mismatched async id",
			pending:    syntheticResponse(uint32(STATUS_PENDING), SMB2_FLAGS_SERVER_TO_REDIR|SMB2_FLAGS_ASYNC_COMMAND, 7, 9, 42),
			completion: syntheticResponse(uint32(STATUS_SUCCESS), SMB2_FLAGS_SERVER_TO_REDIR|SMB2_FLAGS_ASYNC_COMMAND, 7, 10, 42),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &conn{account: openAccount(16), outstandingRequests: newOutstandingRequests()}
			rr := &requestResponse{msgId: 7, creditRequest: 1, recv: make(chan []byte, 1)}
			conn.outstandingRequests.set(7, rr)
			if err := conn.tryHandle(tt.pending, nil); (tt.completion == nil) != (err != nil) {
				t.Fatalf("pending error = %v", err)
			}
			if tt.completion != nil {
				if err := conn.tryHandle(tt.completion, nil); err == nil {
					t.Fatal("mismatched completion was accepted")
				}
			}
		})
	}
}
