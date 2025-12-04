package actions

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
)

func TestBlockIPAction_Validate(t *testing.T) {
	logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)
	action := NewBlockIPAction(logger)

	tests := []struct {
		name    string
		params  map[string]interface{}
		wantErr bool
	}{
		{
			name:    "missing ip_address",
			params:  map[string]interface{}{},
			wantErr: true,
		},
		{
			name:    "empty ip_address",
			params:  map[string]interface{}{"ip_address": ""},
			wantErr: true,
		},
		{
			name:    "invalid ip_address",
			params:  map[string]interface{}{"ip_address": "not-an-ip"},
			wantErr: true,
		},
		{
			name:    "valid IPv4",
			params:  map[string]interface{}{"ip_address": "192.168.1.100"},
			wantErr: false,
		},
		{
			name:    "valid IPv6",
			params:  map[string]interface{}{"ip_address": "2001:db8::1"},
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

func TestUnblockIPAction_Validate(t *testing.T) {
	logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)
	action := NewUnblockIPAction(logger)

	tests := []struct {
		name    string
		params  map[string]interface{}
		wantErr bool
	}{
		{
			name:    "missing ip_address",
			params:  map[string]interface{}{},
			wantErr: true,
		},
		{
			name:    "valid IPv4",
			params:  map[string]interface{}{"ip_address": "10.0.0.1"},
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
