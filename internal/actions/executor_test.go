package actions

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/cisec/aisac-agent/internal/config"
	"github.com/cisec/aisac-agent/pkg/types"
)

func TestNewExecutor(t *testing.T) {
	logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)
	cfg := config.DefaultAgentConfig()

	executor, err := NewExecutor(cfg, logger)
	if err != nil {
		t.Fatalf("NewExecutor failed: %v", err)
	}

	if executor == nil {
		t.Fatal("Expected executor to be non-nil")
	}

	// Verify built-in actions are registered
	actions := executor.ListActions()
	expectedActions := []string{
		"block_ip",
		"unblock_ip",
		"isolate_host",
		"unisolate_host",
		"disable_user",
		"enable_user",
		"kill_process",
	}

	for _, expected := range expectedActions {
		found := false
		for _, action := range actions {
			if action == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected action %s to be registered", expected)
		}
	}
}

func TestExecutor_UnknownAction(t *testing.T) {
	logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)
	cfg := config.DefaultAgentConfig()

	executor, _ := NewExecutor(cfg, logger)

	ctx := context.Background()
	actCtx := types.ActionContext{
		ExecutionID: "test-exec-1",
		CommandID:   "test-cmd-1",
		AgentID:     "test-agent",
		Timeout:     30 * time.Second,
	}

	_, err := executor.Execute(ctx, "unknown_action", nil, actCtx)
	if err == nil {
		t.Error("Expected error for unknown action")
	}
}

// MockAction for testing
type MockAction struct {
	name        types.ActionType
	validateErr error
	executeErr  error
	result      types.ActionResult
}

func (m *MockAction) Name() types.ActionType {
	return m.name
}

func (m *MockAction) Validate(params map[string]interface{}) error {
	return m.validateErr
}

func (m *MockAction) Execute(ctx context.Context, params map[string]interface{}, actCtx types.ActionContext) (types.ActionResult, error) {
	return m.result, m.executeErr
}

func TestExecutor_CustomAction(t *testing.T) {
	logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)
	cfg := config.DefaultAgentConfig()

	executor, _ := NewExecutor(cfg, logger)

	mockAction := &MockAction{
		name: "test_action",
		result: types.ActionResult{
			Success: true,
			Message: "Test completed",
		},
	}

	executor.Register(mockAction)

	ctx := context.Background()
	actCtx := types.ActionContext{
		ExecutionID: "test-exec-1",
		CommandID:   "test-cmd-1",
		AgentID:     "test-agent",
		Timeout:     30 * time.Second,
	}

	result, err := executor.Execute(ctx, "test_action", nil, actCtx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !result.Success {
		t.Error("Expected success to be true")
	}

	if result.Message != "Test completed" {
		t.Errorf("Expected message 'Test completed', got '%s'", result.Message)
	}
}

func TestExecutor_ValidationError(t *testing.T) {
	logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)
	cfg := config.DefaultAgentConfig()

	executor, _ := NewExecutor(cfg, logger)

	mockAction := &MockAction{
		name:        "test_validation",
		validateErr: context.DeadlineExceeded, // Using a standard error
	}

	executor.Register(mockAction)

	ctx := context.Background()
	actCtx := types.ActionContext{
		ExecutionID: "test-exec-1",
		CommandID:   "test-cmd-1",
		AgentID:     "test-agent",
		Timeout:     30 * time.Second,
	}

	result, err := executor.Execute(ctx, "test_validation", nil, actCtx)
	if err == nil {
		t.Error("Expected validation error")
	}

	if result.Success {
		t.Error("Expected success to be false on validation error")
	}
}
