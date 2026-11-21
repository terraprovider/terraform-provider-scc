package main

// This file applies the DLP-specific transforms that the generic generator
// cannot express yet. They keep the generated output self-consistent after the
// dlpIdentityCollections type override in main.go:
//
//   - the schema version is bumped, because v0.2.x stored the workload scopes
//     and NotifyUser as strings while the attributes are now string sets
//     (see internal/provider/dlp_state_upgrade.go for the migration);
//   - Read uses getIdentitySlice so identity-object arrays keep every element;
//   - Create/Update keep the historical "skip empty" write behaviour of the
//     previous string attributes (an empty scope is never marshalled).
//
// Every transform asserts an exact single match so a generator change cannot
// silently drop a patch.

import (
	"fmt"
	"regexp"
)

// dlpReadbackPatches maps a generated resource file to its transform.
var dlpReadbackPatches = map[string]func([]byte) ([]byte, error){
	"dlp_compliance_policy_resource.go": patchDlpCompliancePolicy,
	"dlp_compliance_rule_resource.go":   patchDlpComplianceRule,
}

func patchDlpCompliancePolicy(src []byte) ([]byte, error) {
	var err error
	src, err = bumpSchemaVersion(src)
	if err != nil {
		return nil, err
	}
	for _, field := range []string{"ExchangeLocation", "OneDriveLocation", "SharePointLocation"} {
		src, err = replaceOne(src,
			regexp.MustCompile(fmt.Sprintf(`m\.%s = stringSetValue\(ctx, getStringSlice\(obj, %q\)`, field, field)),
			fmt.Sprintf("m.%s = stringSetValue(ctx, getIdentitySlice(obj, %q)", field, field),
			"policy read "+field)
		if err != nil {
			return nil, err
		}
		src, err = replaceOne(src,
			regexp.MustCompile(fmt.Sprintf(`(?m)^\t\t%s:\s+toStringSlice\(ctx, plan\.%s, &resp\.Diagnostics\),\n`, field, field)),
			"",
			"policy create literal "+field)
		if err != nil {
			return nil, err
		}
	}
	src, err = replaceOne(src,
		regexp.MustCompile(`(\tif v := plan\.EndpointDlpAdaptiveScopes\.ValueString\(\); v != "" \{\n\t\tp\.EndpointDlpAdaptiveScopes = v\n\t\})`),
		`	if v := toStringSlice(ctx, plan.ExchangeLocation, &resp.Diagnostics); len(v) > 0 {
		p.ExchangeLocation = v
	}
	if v := toStringSlice(ctx, plan.OneDriveLocation, &resp.Diagnostics); len(v) > 0 {
		p.OneDriveLocation = v
	}
	if v := toStringSlice(ctx, plan.SharePointLocation, &resp.Diagnostics); len(v) > 0 {
		p.SharePointLocation = v
	}
	$1`,
		"policy create guards")
	return src, err
}

func patchDlpComplianceRule(src []byte) ([]byte, error) {
	var err error
	src, err = bumpSchemaVersion(src)
	if err != nil {
		return nil, err
	}
	src, err = replaceOne(src,
		regexp.MustCompile(`m\.NotifyUser = stringSetValue\(ctx, getStringSlice\(obj, "NotifyUser"\)`),
		`m.NotifyUser = stringSetValue(ctx, getIdentitySlice(obj, "NotifyUser")`,
		"rule read NotifyUser")
	if err != nil {
		return nil, err
	}
	src, err = replaceOne(src,
		regexp.MustCompile(`(?m)^\t\tNotifyUser:\s+toStringSlice\(ctx, plan\.NotifyUser, &resp\.Diagnostics\),\n`),
		"",
		"rule create literal NotifyUser")
	if err != nil {
		return nil, err
	}
	src, err = replaceOne(src,
		regexp.MustCompile(`(\tif v := plan\.NotifyUserType\.ValueString\(\); v != "" \{\n\t\tp\.NotifyUserType = v\n\t\})`),
		`	if v := toStringSlice(ctx, plan.NotifyUser, &resp.Diagnostics); len(v) > 0 {
		p.NotifyUser = v
	}
	$1`,
		"rule create guard NotifyUser")
	if err != nil {
		return nil, err
	}
	src, err = replaceOne(src,
		regexp.MustCompile(`(?m)^\tsp\.NotifyUser = toStringSlice\(ctx, plan\.NotifyUser, &resp\.Diagnostics\)\n`),
		`	if v := toStringSlice(ctx, plan.NotifyUser, &resp.Diagnostics); len(v) > 0 {
		sp.NotifyUser = v
	}
`,
		"rule update guard NotifyUser")
	return src, err
}

// bumpSchemaVersion declares the first schema version of a resource whose
// state shape changed (string -> set), enabling UpgradeState migrations.
func bumpSchemaVersion(src []byte) ([]byte, error) {
	return replaceOne(src,
		regexp.MustCompile(`resp\.Schema = schema\.Schema\{\n`),
		"resp.Schema = schema.Schema{\n\t\tVersion: 1,\n",
		"schema version")
}

func replaceOne(src []byte, re *regexp.Regexp, replacement, what string) ([]byte, error) {
	matches := re.FindAll(src, -1)
	if len(matches) != 1 {
		return nil, fmt.Errorf("%s: expected exactly one match for %s, found %d", what, re, len(matches))
	}
	return re.ReplaceAll(src, []byte(replacement)), nil
}
