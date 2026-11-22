package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/terraprovider/go-exoscc/adminapi"
)

// policyConfigSingletonIdentity is the Identity Set-PolicyConfig accepts for the
// tenant singleton. Get-PolicyConfig also accepts the object's Guid, but Set
// with that Guid returns HTTP 500.
const policyConfigSingletonIdentity = "Settings"

// endpointSettingParam is one PswsHashtable entry. Field order is the order
// the admin API accepted (Value, then Setting). encoding/json sorts map keys,
// which puts Setting first and is not the payload that returned HTTP 200.
type endpointSettingParam struct {
	Value   string `json:"Value"`
	Setting string `json:"Setting"`
}

// applyEndpointDlpGlobalSettings writes EndpointDlpGlobalSettings and nothing else.
//
// Set-PolicyConfig replaces that list. Sending the rest of the read-back object
// (ReservedForFutureUse and the group JSON blobs) returns HTTP 400 Invalid
// Operation. One JSON array string also returns HTTP 400. The call that
// returned HTTP 200 sent Identity "Settings" and an array of objects.
func (r *policyConfigResource) applyEndpointDlpGlobalSettings(ctx context.Context, plan policyConfigModel, state *policyConfigModel, diags *diag.Diagnostics) error {
	if state != nil && plan.EndpointDlpGlobalSettings.Equal(state.EndpointDlpGlobalSettings) {
		return nil
	}
	raw := toStringSlice(ctx, plan.EndpointDlpGlobalSettings, diags)
	if diags.HasError() {
		return fmt.Errorf("endpoint dlp global settings could not be read from the plan")
	}
	params, err := endpointDlpSetParams(raw)
	if err != nil {
		return err
	}
	_, err = r.client.Admin.Invoke(ctx, "Set-PolicyConfig", params)
	if err == nil {
		return nil
	}
	sent, merr := json.Marshal(params)
	if merr != nil {
		return annotateAdminError(err)
	}
	return fmt.Errorf("%w; sent: %s", annotateAdminError(err), truncate(string(sent), 1500))
}

func annotateAdminError(err error) error {
	var apiErr *adminapi.APIError
	if err == nil || !errors.As(err, &apiErr) || len(apiErr.InnerRaw) == 0 {
		return err
	}
	return fmt.Errorf("%w; inner: %s", err, truncate(string(apiErr.InnerRaw), 1500))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func endpointDlpSetParams(raw []string) (map[string]any, error) {
	settings, err := hashtableEndpointSettings(raw)
	if err != nil {
		return nil, err
	}
	if len(settings) == 0 {
		return nil, fmt.Errorf("refusing to clear EndpointDlpGlobalSettings")
	}
	return map[string]any{
		"Identity":                  policyConfigSingletonIdentity,
		"EndpointDlpGlobalSettings": settings,
	}, nil
}

func hashtableEndpointSettings(raw []string) ([]endpointSettingParam, error) {
	out := make([]endpointSettingParam, 0, len(raw))
	for _, item := range raw {
		parsed, err := parseEndpointSettingElements(item)
		if err != nil {
			return nil, err
		}
		for _, element := range parsed {
			object, ok := element.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("endpoint dlp setting must be an object, got %T", element)
			}
			setting, ok := endpointSettingField(object, "Setting")
			if !ok || setting == "" {
				return nil, fmt.Errorf("endpoint dlp setting is missing Setting")
			}
			value, ok := endpointSettingField(object, "Value")
			if !ok {
				return nil, fmt.Errorf("endpoint dlp setting %s is missing Value", setting)
			}
			out = append(out, endpointSettingParam{Value: value, Setting: setting})
		}
	}
	return out, nil
}

func endpointSettingField(object map[string]any, want string) (string, bool) {
	for key, value := range object {
		if !strings.EqualFold(key, want) {
			continue
		}
		return endpointSettingScalar(value)
	}
	return "", false
}

func endpointDlpGlobalSettingStrings(obj map[string]any) []string {
	value, ok := obj["EndpointDlpGlobalSettings"]
	if !ok || value == nil {
		return nil
	}
	return canonicalEndpointSettingElements(value)
}

func canonicalEndpointSettingElements(value any) []string {
	switch typed := value.(type) {
	case string:
		parsed, err := parseEndpointSettingElements(typed)
		if err != nil {
			return []string{typed}
		}
		return canonicalizeEndpointElements(parsed)
	case []any:
		return canonicalizeEndpointElements(typed)
	case map[string]any:
		if encoded, ok := canonicalEndpointSetting(typed); ok {
			return []string{encoded}
		}
	}
	return nil
}

func canonicalizeEndpointElements(elements []any) []string {
	out := make([]string, 0, len(elements))
	for _, element := range elements {
		switch typed := element.(type) {
		case string:
			out = append(out, canonicalEndpointSettingElements(typed)...)
		case map[string]any:
			if encoded, ok := canonicalEndpointSetting(typed); ok {
				out = append(out, encoded)
			}
		}
	}
	return out
}

func parseEndpointSettingElements(raw string) ([]any, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("endpoint dlp setting is empty")
	}
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, fmt.Errorf("endpoint dlp setting is not JSON: %w", err)
	}
	switch typed := parsed.(type) {
	case []any:
		return typed, nil
	case map[string]any:
		return []any{typed}, nil
	default:
		return nil, fmt.Errorf("endpoint dlp setting must be an object or array, got %T", parsed)
	}
}

func canonicalEndpointSetting(setting map[string]any) (string, bool) {
	normalized := make(map[string]string, len(setting))
	for key, value := range setting {
		name := key
		if strings.EqualFold(key, "Setting") {
			name = "Setting"
		} else if strings.EqualFold(key, "Value") {
			name = "Value"
		}
		text, ok := endpointSettingScalar(value)
		if !ok {
			return "", false
		}
		normalized[name] = text
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "", false
	}
	return string(encoded), true
}

func endpointSettingScalar(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, true
	case bool:
		if typed {
			return "true", true
		}
		return "false", true
	case float64:
		if typed == math.Trunc(typed) {
			return strconv.FormatInt(int64(typed), 10), true
		}
		return strconv.FormatFloat(typed, 'f', -1, 64), true
	default:
		return "", false
	}
}
