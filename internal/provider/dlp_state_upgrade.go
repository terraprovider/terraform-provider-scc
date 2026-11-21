package provider

// State migration for the DLP workload-scope / NotifyUser collections.
//
// Schema version 0 (provider <= 0.2.x) declared exchange_location,
// one_drive_location, share_point_location and notify_user as strings, which
// silently lost every JSON array the service read back. Version 1 declares
// them as string sets. Version 0 state is migrated here without fabricating
// values: an empty string becomes an empty set, a non-empty scalar becomes a
// single-element set, arrays and nulls are preserved as-is.

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

var (
	_ resource.ResourceWithUpgradeState = &dlpCompliancePolicyResource{}
	_ resource.ResourceWithUpgradeState = &dlpComplianceRuleResource{}
)

func (r *dlpCompliancePolicyResource) UpgradeState(_ context.Context) map[int64]resource.StateUpgrader {
	return map[int64]resource.StateUpgrader{
		0: {StateUpgrader: r.upgradeStateV0},
	}
}

func (r *dlpCompliancePolicyResource) upgradeStateV0(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
	setStateUpgrader(ctx, req, resp, r.Schema, "exchange_location", "one_drive_location", "share_point_location")
}

func (r *dlpComplianceRuleResource) UpgradeState(_ context.Context) map[int64]resource.StateUpgrader {
	return map[int64]resource.StateUpgrader{
		0: {StateUpgrader: r.upgradeStateV0},
	}
}

func (r *dlpComplianceRuleResource) upgradeStateV0(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
	setStateUpgrader(ctx, req, resp, r.Schema, "notify_user")
}

// setStateUpgrader rewrites the named scalar attributes of a raw v0 state into
// arrays so the state decodes against the v1 set schema.
func setStateUpgrader(
	ctx context.Context,
	req resource.UpgradeStateRequest,
	resp *resource.UpgradeStateResponse,
	schemaFn func(context.Context, resource.SchemaRequest, *resource.SchemaResponse),
	keys ...string,
) {
	if req.RawState == nil || len(req.RawState.JSON) == 0 {
		resp.Diagnostics.AddError("Invalid prior state", "the stored state has no JSON payload to upgrade")
		return
	}
	var raw map[string]any
	if err := json.Unmarshal(req.RawState.JSON, &raw); err != nil {
		resp.Diagnostics.AddError("Invalid prior state", err.Error())
		return
	}
	for _, key := range keys {
		switch v := raw[key].(type) {
		case string:
			if v == "" {
				raw[key] = []any{}
			} else {
				raw[key] = []any{v}
			}
		case nil, []any:
			// null and already-migrated arrays need no change
		default:
			resp.Diagnostics.AddError("Invalid prior state", "unexpected value for "+key)
			return
		}
	}
	upgraded, err := json.Marshal(raw)
	if err != nil {
		resp.Diagnostics.AddError("Unable to upgrade state", err.Error())
		return
	}
	var schemaResp resource.SchemaResponse
	schemaFn(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		resp.Diagnostics.Append(schemaResp.Diagnostics...)
		return
	}
	value, err := tftypes.ValueFromJSON(upgraded, schemaResp.Schema.Type().TerraformType(ctx))
	if err != nil {
		resp.Diagnostics.AddError("Unable to upgrade state", err.Error())
		return
	}
	resp.State = tfsdk.State{Schema: schemaResp.Schema, Raw: value}
}
