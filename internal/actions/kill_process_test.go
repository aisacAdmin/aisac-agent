package actions

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
)

func TestKillProcessAction_Validate(t *testing.T) {
	logger := zerolog.New(os.Stdout).Level(zerolog.Disabled)
	action := NewKillProcessAction(logger)

	tests := []struct {
		name    string
		params  map[string]interface{}
		wantErr bool
	}{
		{
			name:    "no pid or process_name",
			params:  map[string]interface{}{},
			wantErr: true,
		},
		{
			name:    "valid pid as float64",
			params:  map[string]interface{}{"pid": float64(1234)},
			wantErr: false,
		},
		{
			name:    "valid pid as int",
			params:  map[string]interface{}{"pid": 1234},
			wantErr: false,
		},
		{
			name:    "invalid pid zero",
			params:  map[string]interface{}{"pid": float64(0)},
			wantErr: true,
		},
		{
			name:    "invalid pid negative",
			params:  map[string]interface{}{"pid": float64(-1)},
			wantErr: true,
		},
		{
			name:    "valid process_name",
			params:  map[string]interface{}{"process_name": "firefox"},
			wantErr: false,
		},
		{
			name:    "empty process_name",
			params:  map[string]interface{}{"process_name": ""},
			wantErr: true,
		},
		{
			name:    "both pid and process_name",
			params:  map[string]interface{}{"pid": float64(1234), "process_name": "firefox"},
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
