package provider

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// Fixtures mirror nonsecret exports captured 2026-10-07 with the Savex Purview
// discovery inventory (infrastructure/purview/discovery):
//
//	purview_dlp_policies.json: ExchangeLocation is an array of identity
//	objects ({Name, ImmutableIdentity, Guid, ...}); OneDriveLocation and
//	SharePointLocation are empty arrays.
//	purview_dlp_rules.json: NotifyUser is an array of scalars (["LastModifier"]).
func capturedLocationElement(name, guid string) map[string]any {
	return map[string]any{
		"DisplayName":       name,
		"Name":              name,
		"ImmutableIdentity": name,
		"Guid":              guid,
		"Type":              map[string]any{"value": 1, "Value": "Tenant"},
		"Workload":          map[string]any{"value": 1, "Value": "Exchange"},
	}
}

func setElements(t *testing.T, s types.Set) []string {
	t.Helper()
	out := []string{}
	for _, e := range s.Elements() {
		str, ok := e.(types.String)
		if !ok {
			t.Fatalf("set element is not a string: %#v", e)
		}
		out = append(out, str.ValueString())
	}
	sort.Strings(out)
	return out
}

func assertSet(t *testing.T, what string, got types.Set, want []string) {
	t.Helper()
	if got.IsNull() || got.IsUnknown() {
		t.Fatalf("%s is null/unknown, want set %v", what, want)
	}
	if len(want) == 0 {
		if elements := setElements(t, got); len(elements) != 0 {
			t.Errorf("%s = %v, want empty set", what, elements)
		}
		return
	}
	wantSorted := append([]string(nil), want...)
	sort.Strings(wantSorted)
	if elements := setElements(t, got); !reflect.DeepEqual(elements, wantSorted) {
		t.Errorf("%s = %v, want %v", what, elements, wantSorted)
	}
}

func TestGetIdentitySlice(t *testing.T) {
	t.Parallel()
	obj := map[string]any{
		"CapturedAll":   []any{capturedLocationElement("All", "00000000-0000-0000-0000-000000000001")},
		"Empty":         []any{},
		"Scalars":       []any{"LastModifier", "Owner"},
		"Missing":       nil,
		"MultiIdentity": []any{capturedLocationElement("All", "g1"), capturedLocationElement("Second", "g2"), "legacy-string"},
		"NoIdentity":    []any{map[string]any{"DisplayName": "opaque"}},
	}
	cases := []struct {
		key  string
		want []string
	}{
		{"CapturedAll", []string{"All"}},
		{"Empty", []string{}},
		{"Scalars", []string{"LastModifier", "Owner"}},
		{"Missing", nil},
		{"MultiIdentity", []string{"All", "Second", "legacy-string"}},
		{"NoIdentity", []string{}},
	}
	for _, tc := range cases {
		got := getIdentitySlice(obj, tc.key)
		if len(got) == 0 && len(tc.want) == 0 {
			continue
		}
		sort.Strings(got)
		want := append([]string(nil), tc.want...)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", tc.key, got, want)
		}
	}
}

func TestReadDlpCompliancePolicyCollections(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Captured shape: tenant-wide Exchange scope as an identity object, empty
	// OneDrive/SharePoint arrays.
	adaptive := map[string]any{
		"Name":               "Adaptive Protection policy for Teams and Exchange DLP",
		"ExchangeLocation":   []any{capturedLocationElement("All", "00000000-0000-0000-0000-000000000001")},
		"OneDriveLocation":   []any{},
		"SharePointLocation": []any{},
	}
	var m dlpCompliancePolicyModel
	readDlpCompliancePolicy(ctx, adaptive, &m)
	assertSet(t, "ExchangeLocation", m.ExchangeLocation, []string{"All"})
	assertSet(t, "OneDriveLocation", m.OneDriveLocation, []string{})
	assertSet(t, "SharePointLocation", m.SharePointLocation, []string{})

	// Multiple identities must all survive a read-back.
	multi := map[string]any{
		"ExchangeLocation": []any{
			capturedLocationElement("All", "g1"),
			capturedLocationElement("Executives", "g2"),
			capturedLocationElement("Risk", "g3"),
		},
	}
	readDlpCompliancePolicy(ctx, multi, &m)
	assertSet(t, "multi-element ExchangeLocation", m.ExchangeLocation, []string{"All", "Executives", "Risk"})

	// Read observes remote drift: a previously populated scope that the service
	// now reports as empty must be emptied, not kept from prior state.
	readDlpCompliancePolicy(ctx, map[string]any{"ExchangeLocation": []any{}}, &m)
	assertSet(t, "ExchangeLocation after remote scope removal", m.ExchangeLocation, []string{})

	// Every workload scope preserves multiple identities and observes drift.
	readDlpCompliancePolicy(ctx, map[string]any{
		"OneDriveLocation": []any{
			capturedLocationElement("exec@contoso.com", "od1"),
			capturedLocationElement("risk@contoso.com", "od2"),
		},
		"SharePointLocation": []any{
			capturedLocationElement("contoso.sharepoint.com/sites/Risk", "sp1"),
		},
	}, &m)
	assertSet(t, "multi-element OneDriveLocation", m.OneDriveLocation, []string{"exec@contoso.com", "risk@contoso.com"})
	assertSet(t, "SharePointLocation", m.SharePointLocation, []string{"contoso.sharepoint.com/sites/Risk"})
	readDlpCompliancePolicy(ctx, map[string]any{
		"OneDriveLocation":   []any{},
		"SharePointLocation": []any{capturedLocationElement("contoso.sharepoint.com/sites/Other", "sp2")},
	}, &m)
	assertSet(t, "OneDriveLocation after remote scope removal", m.OneDriveLocation, []string{})
	assertSet(t, "SharePointLocation after remote replacement", m.SharePointLocation, []string{"contoso.sharepoint.com/sites/Other"})

	// Set semantics are order-insensitive: a reordered remote array yields an
	// Equal value (so RequiresReplace on matching state cannot trigger), while
	// different membership does not (meaningful drift stays detectable).
	var reordered dlpCompliancePolicyModel
	readDlpCompliancePolicy(ctx, map[string]any{
		"ExchangeLocation": []any{
			capturedLocationElement("First", "g1"),
			capturedLocationElement("Second", "g2"),
		},
	}, &m)
	readDlpCompliancePolicy(ctx, map[string]any{
		"ExchangeLocation": []any{
			capturedLocationElement("Second", "g2"),
			capturedLocationElement("First", "g1"),
		},
	}, &reordered)
	if !m.ExchangeLocation.Equal(reordered.ExchangeLocation) {
		t.Errorf("reordered scope reads must be Equal: %v vs %v",
			setElements(t, m.ExchangeLocation), setElements(t, reordered.ExchangeLocation))
	}
	readDlpCompliancePolicy(ctx, map[string]any{
		"ExchangeLocation": []any{capturedLocationElement("Third", "g3")},
	}, &reordered)
	if m.ExchangeLocation.Equal(reordered.ExchangeLocation) {
		t.Error("changed remote scope must not Equal prior read")
	}
}

func TestReadDlpComplianceRuleNotifyUserCollections(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	captured := map[string]any{
		"Name":       "Adaptive Protection block rule for Teams and Exchange DLP",
		"NotifyUser": []any{"LastModifier"},
	}
	var m dlpComplianceRuleModel
	readDlpComplianceRule(ctx, captured, &m)
	assertSet(t, "NotifyUser", m.NotifyUser, []string{"LastModifier"})

	readDlpComplianceRule(ctx, map[string]any{"NotifyUser": []any{"LastModifier", "Owner"}}, &m)
	assertSet(t, "multi-element NotifyUser", m.NotifyUser, []string{"LastModifier", "Owner"})

	// Remote drift: notifications removed remotely must empty the state.
	readDlpComplianceRule(ctx, map[string]any{"NotifyUser": []any{}}, &m)
	assertSet(t, "NotifyUser after remote removal", m.NotifyUser, []string{})
}

func assertSetAttribute(t *testing.T, attrs map[string]schema.Attribute, name string, requireReplacement bool) {
	t.Helper()
	attr, ok := attrs[name]
	if !ok {
		t.Fatalf("schema missing %s", name)
	}
	setAttr, ok := attr.(schema.SetAttribute)
	if !ok {
		t.Fatalf("%s is %T, want schema.SetAttribute", name, attr)
	}
	hasReplace := false
	for _, pm := range setAttr.PlanModifiers {
		if strings.Contains(strings.ToLower(fmt.Sprintf("%T", pm)), "requiresreplace") {
			hasReplace = true
		}
	}
	if hasReplace != requireReplacement {
		t.Errorf("%s RequiresReplace = %v, want %v", name, hasReplace, requireReplacement)
	}
}

func TestDlpCollectionSchemaIsSetAtVersionOne(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var policySchema resource.SchemaResponse
	(&dlpCompliancePolicyResource{}).Schema(ctx, resource.SchemaRequest{}, &policySchema)
	if policySchema.Diagnostics.HasError() {
		t.Fatalf("policy schema diagnostics: %v", policySchema.Diagnostics)
	}
	if policySchema.Schema.Version != 1 {
		t.Errorf("policy schema version = %d, want 1", policySchema.Schema.Version)
	}
	assertSetAttribute(t, policySchema.Schema.Attributes, "exchange_location", true)
	assertSetAttribute(t, policySchema.Schema.Attributes, "one_drive_location", true)
	assertSetAttribute(t, policySchema.Schema.Attributes, "share_point_location", true)

	var ruleSchema resource.SchemaResponse
	(&dlpComplianceRuleResource{}).Schema(ctx, resource.SchemaRequest{}, &ruleSchema)
	if ruleSchema.Diagnostics.HasError() {
		t.Fatalf("rule schema diagnostics: %v", ruleSchema.Diagnostics)
	}
	if ruleSchema.Schema.Version != 1 {
		t.Errorf("rule schema version = %d, want 1", ruleSchema.Schema.Version)
	}
	assertSetAttribute(t, ruleSchema.Schema.Attributes, "notify_user", false)
}

func TestDlpStateUpgradeFromV0(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, r := range []resource.ResourceWithUpgradeState{&dlpCompliancePolicyResource{}, &dlpComplianceRuleResource{}} {
		upgraders := r.UpgradeState(ctx)
		if _, ok := upgraders[0]; !ok {
			t.Errorf("%T has no version 0 upgrader", r)
		}
	}

	policyRaw := []byte(`{
		"id": "bde14d3a-4c26-4c2c-9b8a-72d1459a6c45",
		"identity": "Adaptive Protection policy for Teams and Exchange DLP",
		"exchange_location": "",
		"one_drive_location": "All",
		"share_point_location": null,
		"comment": "kept"
	}`)
	var policyResp resource.UpgradeStateResponse
	(&dlpCompliancePolicyResource{}).upgradeStateV0(ctx,
		resource.UpgradeStateRequest{RawState: &tfprotov6.RawState{JSON: policyRaw}}, &policyResp)
	if policyResp.Diagnostics.HasError() {
		t.Fatalf("policy upgrade diagnostics: %v", policyResp.Diagnostics)
	}
	var policy dlpCompliancePolicyModel
	if d := policyResp.State.Get(ctx, &policy); d.HasError() {
		t.Fatalf("upgraded policy state does not decode: %v", d)
	}
	assertSet(t, "upgraded exchange_location", policy.ExchangeLocation, []string{})
	assertSet(t, "upgraded one_drive_location", policy.OneDriveLocation, []string{"All"})
	if !policy.SharePointLocation.IsNull() {
		t.Errorf("upgraded share_point_location = %v, want null preserved", policy.SharePointLocation)
	}
	if policy.Comment.ValueString() != "kept" {
		t.Errorf("upgraded comment = %q, want preserved value", policy.Comment.ValueString())
	}

	ruleRaw := []byte(`{
		"id": "rule-guid",
		"identity": "Adaptive Protection block rule for Teams and Exchange DLP",
		"notify_user": "LastModifier",
		"disabled": false
	}`)
	var ruleResp resource.UpgradeStateResponse
	(&dlpComplianceRuleResource{}).upgradeStateV0(ctx,
		resource.UpgradeStateRequest{RawState: &tfprotov6.RawState{JSON: ruleRaw}}, &ruleResp)
	if ruleResp.Diagnostics.HasError() {
		t.Fatalf("rule upgrade diagnostics: %v", ruleResp.Diagnostics)
	}
	var rule dlpComplianceRuleModel
	if d := ruleResp.State.Get(ctx, &rule); d.HasError() {
		t.Fatalf("upgraded rule state does not decode: %v", d)
	}
	assertSet(t, "upgraded notify_user", rule.NotifyUser, []string{"LastModifier"})
}
