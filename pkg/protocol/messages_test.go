package protocol

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cisec/aisac-agent/pkg/types"
)

func TestNewMessage(t *testing.T) {
	payload := map[string]string{"key": "value"}

	msg, err := NewMessage(MessageTypeCommand, payload)
	if err != nil {
		t.Fatalf("NewMessage failed: %v", err)
	}

	if msg.ID == "" {
		t.Error("Expected message ID to be set")
	}

	if msg.Type != MessageTypeCommand {
		t.Errorf("Expected type %s, got %s", MessageTypeCommand, msg.Type)
	}

	if msg.Timestamp.IsZero() {
		t.Error("Expected timestamp to be set")
	}

	if len(msg.Payload) == 0 {
		t.Error("Expected payload to be set")
	}
}

func TestMessage_ParsePayload(t *testing.T) {
	original := Command{
		ID:            "cmd-123",
		Action:        types.ActionBlockIP,
		Parameters:    map[string]interface{}{"ip_address": "192.168.1.1"},
		ExecutionID:   "exec-456",
		TimeoutSeconds: 30,
	}

	msg, err := NewMessage(MessageTypeCommand, original)
	if err != nil {
		t.Fatalf("NewMessage failed: %v", err)
	}

	var parsed Command
	if err := msg.ParsePayload(&parsed); err != nil {
		t.Fatalf("ParsePayload failed: %v", err)
	}

	if parsed.ID != original.ID {
		t.Errorf("Expected ID %s, got %s", original.ID, parsed.ID)
	}

	if parsed.Action != original.Action {
		t.Errorf("Expected action %s, got %s", original.Action, parsed.Action)
	}

	if parsed.ExecutionID != original.ExecutionID {
		t.Errorf("Expected execution_id %s, got %s", original.ExecutionID, parsed.ExecutionID)
	}
}

func TestCommand_JSON(t *testing.T) {
	cmd := Command{
		ID:            "cmd-123",
		Action:        types.ActionBlockIP,
		Parameters:    map[string]interface{}{"ip_address": "192.168.1.1", "duration": float64(3600)},
		ExecutionID:   "exec-456",
		TimeoutSeconds: 30,
		Priority:      1,
	}

	data, err := json.Marshal(cmd)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed Command
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.ID != cmd.ID {
		t.Errorf("Expected ID %s, got %s", cmd.ID, parsed.ID)
	}

	if parsed.TimeoutSeconds != cmd.TimeoutSeconds {
		t.Errorf("Expected timeout %d, got %d", cmd.TimeoutSeconds, parsed.TimeoutSeconds)
	}
}

func TestResponse_JSON(t *testing.T) {
	resp := Response{
		ID:              "resp-123",
		CommandID:       "cmd-456",
		Status:          types.StatusSuccess,
		Result:          types.ActionResult{Success: true, Message: "OK"},
		ExecutionTimeMs: 150,
		Timestamp:       time.Now().UTC(),
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed Response
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.CommandID != resp.CommandID {
		t.Errorf("Expected CommandID %s, got %s", resp.CommandID, parsed.CommandID)
	}

	if parsed.Status != types.StatusSuccess {
		t.Errorf("Expected status success, got %s", parsed.Status)
	}

	if parsed.ExecutionTimeMs != resp.ExecutionTimeMs {
		t.Errorf("Expected ExecutionTimeMs %d, got %d", resp.ExecutionTimeMs, parsed.ExecutionTimeMs)
	}
}

func TestHeartbeat_JSON(t *testing.T) {
	hb := Heartbeat{
		AgentID:     "agent-123",
		Timestamp:   time.Now().UTC(),
		Status:      "connected",
		ActiveTasks: []string{"task-1", "task-2"},
		Metrics: &AgentMetrics{
			CPUPercent:    25.5,
			MemoryPercent: 60.0,
			DiskPercent:   45.0,
			Uptime:        3600,
		},
	}

	data, err := json.Marshal(hb)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed Heartbeat
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.AgentID != hb.AgentID {
		t.Errorf("Expected AgentID %s, got %s", hb.AgentID, parsed.AgentID)
	}

	if len(parsed.ActiveTasks) != 2 {
		t.Errorf("Expected 2 active tasks, got %d", len(parsed.ActiveTasks))
	}

	if parsed.Metrics == nil {
		t.Fatal("Expected metrics to be set")
	}

	if parsed.Metrics.CPUPercent != 25.5 {
		t.Errorf("Expected CPUPercent 25.5, got %f", parsed.Metrics.CPUPercent)
	}
}

func TestRegisterRequest_JSON(t *testing.T) {
	req := RegisterRequest{
		AgentInfo: types.AgentInfo{
			ID:       "agent-123",
			Hostname: "server1",
			Platform: types.PlatformLinux,
			Version:  "1.0.0",
		},
		Capabilities: []string{"block_ip", "isolate_host"},
		Version:      "1.0.0",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed RegisterRequest
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.AgentInfo.ID != req.AgentInfo.ID {
		t.Errorf("Expected AgentInfo.ID %s, got %s", req.AgentInfo.ID, parsed.AgentInfo.ID)
	}

	if len(parsed.Capabilities) != 2 {
		t.Errorf("Expected 2 capabilities, got %d", len(parsed.Capabilities))
	}
}

func TestMessageTypes(t *testing.T) {
	// Verify message type constants
	types := []MessageType{
		MessageTypeCommand,
		MessageTypePing,
		MessageTypeConfig,
		MessageTypeCancel,
		MessageTypeResponse,
		MessageTypePong,
		MessageTypeHeartbeat,
		MessageTypeRegister,
	}

	for _, msgType := range types {
		if msgType == "" {
			t.Error("Message type should not be empty")
		}
	}
}
