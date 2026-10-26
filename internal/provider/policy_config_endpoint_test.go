package provider

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/terraprovider/go-exoscc/adminapi"
)

func TestCanonicalEndpointSettingBoolAndNumber(t *testing.T) {
	obj := map[string]any{
		"EndpointDlpGlobalSettings": []any{
			map[string]any{"Value": true, "Setting": "AdvancedClassificationEnabled"},
			map[string]any{"setting": "DailyBandwidthLimitInMB", "value": float64(1000)},
		},
	}
	got := endpointDlpGlobalSettingStrings(obj)
	want := []string{
		`{"Setting":"AdvancedClassificationEnabled","Value":"true"}`,
		`{"Setting":"DailyBandwidthLimitInMB","Value":"1000"}`,
	}
	if len(got) != len(want) {
		t.Fatalf("len %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestHashtableEndpointSettingsExpandsArrayString(t *testing.T) {
	raw := []string{
		`[{"Setting":"CloudAppMode","Value":"Allow"},{"Setting":"CloudAppRestrictionList","Value":"*.savex-internal.com"}]`,
	}
	got, err := hashtableEndpointSettings(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("len %d, want 2", len(got))
	}
	if got[0].Setting != "CloudAppMode" || got[0].Value != "Allow" {
		t.Fatalf("first = %#v", got[0])
	}
}

func TestEndpointDlpSetParamsMatchesAcceptedPayload(t *testing.T) {
	params, err := endpointDlpSetParams([]string{
		`{"Setting":"CloudAppMode","Value":"Allow"}`,
		`{"value":true,"setting":"AdvancedClassificationEnabled"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"EndpointDlpGlobalSettings":[{"Value":"Allow","Setting":"CloudAppMode"},{"Value":"true","Setting":"AdvancedClassificationEnabled"}],"Identity":"Settings"}`
	if string(encoded) != want {
		t.Fatalf("payload = %s", encoded)
	}
}

func TestAnnotateAdminErrorIncludesInner(t *testing.T) {
	base := &adminapi.APIError{Status: 500, Code: "InternalServerError", Message: "Error executing cmdlet"}
	base.InnerRaw = []byte(`{"message":"bad setting"}`)
	got := annotateAdminError(base)
	if !strings.Contains(got.Error(), "bad setting") {
		t.Fatalf("error = %s", got)
	}
	if !errors.Is(got, base) {
		t.Fatal("wrapped error should unwrap to the API error")
	}
}

func TestHashtableEndpointSettingsRejectsText(t *testing.T) {
	if _, err := hashtableEndpointSettings([]string{"Allow"}); err == nil {
		t.Fatal("expected error")
	}
}
