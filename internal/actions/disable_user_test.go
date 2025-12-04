package actions

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
)

func TestDisableUserAction_Validate(t *testing.T) {
	logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)
	action := NewDisableUserAction(logger)

	tests := []struct {
		name    string
		params  map[string]interface{}
		wantErr bool
	}{
		{
			name:    "missing username",
			params:  map[string]interface{}{},
			wantErr: true,
		},
		{
			name:    "empty username",
			params:  map[string]interface{}{"username": ""},
			wantErr: true,
		},
		{
			name:    "protected user root",
			params:  map[string]interface{}{"username": "root"},
			wantErr: true,
		},
		{
			name:    "protected user Administrator",
			params:  map[string]interface{}{"username": "Administrator"},
			wantErr: true,
		},
		{
			name:    "protected user SYSTEM",
			params:  map[string]interface{}{"username": "SYSTEM"},
			wantErr: true,
		},
		{
			name:    "valid username",
			params:  map[string]interface{}{"username": "testuser"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := action.Validate(tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEnableUserAction_Validate(t *testing.T) {
	logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)
	action := NewEnableUserAction(logger)

	tests := []struct {
		name    string
		params  map[string]interface{}
		wantErr bool
	}{
		{
			name:    "missing username",
			params:  map[string]interface{}{},
			wantErr: true,
		},
		{
			name:    "empty username",
			params:  map[string]interface{}{"username": ""},
			wantErr: true,
		},
		{
			name:    "valid username",
			params:  map[string]interface{}{"username": "testuser"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := action.Validate(tt.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
