package main

import (
	"encoding/json"
	"io"
)

type HookInput struct {
	ToolName  string    `json:"tool_name"`
	ToolInput ToolInput `json:"tool_input"`
	Cwd       string    `json:"cwd"`
}

type ToolInput struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

type HookOutput struct {
	HookSpecificOutput HookSpecificOutput `json:"hookSpecificOutput"`
}

type HookSpecificOutput struct {
	HookEventName string   `json:"hookEventName"`
	Decision      Decision `json:"decision"`
}

type Decision struct {
	Behavior string `json:"behavior"`
	Message  string `json:"message,omitempty"`
}

func readInput(r io.Reader) (*HookInput, error) {
	var input HookInput
	if err := json.NewDecoder(r).Decode(&input); err != nil {
		return nil, err
	}
	return &input, nil
}

func writeAllow(w io.Writer) error {
	return json.NewEncoder(w).Encode(HookOutput{
		HookSpecificOutput: HookSpecificOutput{
			HookEventName: "PermissionRequest",
			Decision:      Decision{Behavior: "allow"},
		},
	})
}

func writeDeny(w io.Writer, message string) error {
	return json.NewEncoder(w).Encode(HookOutput{
		HookSpecificOutput: HookSpecificOutput{
			HookEventName: "PermissionRequest",
			Decision:      Decision{Behavior: "deny", Message: message},
		},
	})
}
