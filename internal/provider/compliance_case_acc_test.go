package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// TestAccComplianceCase_basic exercises the full lifecycle of scc_compliance_case
// against a live tenant: create (with a data-source read-back), import, and an
// in-place update. Compliance cases are the simplest CRUD-complete Purview object
// (New-ComplianceCase -Name), so they make a good end-to-end smoke test. Run with
// TF_ACC=1 and ARM_* credentials pointing at a disposable dev tenant.
func TestAccComplianceCase_basic(t *testing.T) {
	name := acctest.RandomWithPrefix("tf-acc-case")
	const resourceName = "scc_compliance_case.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{ // create + data source lookup
				Config: testAccComplianceCaseConfig(name, "Acc created"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "description", "Acc created"),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "identity"),
					// singular lookup by identity
					resource.TestCheckResourceAttr("data.scc_compliance_case.by_identity", "description", "Acc created"),
					resource.TestCheckResourceAttrPair("data.scc_compliance_case.by_identity", "id", resourceName, "id"),
					// plural list-all returns at least the case we just created
					resource.TestCheckResourceAttrSet("data.scc_compliance_cases.all", "compliance_cases.#"),
				),
			},
			{ // import by identity.
				// Placed before the update so the verify reads a value that has had
				// time to propagate across sessions, avoiding eventual-consistency flakes.
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					return s.RootModule().Resources[resourceName].Primary.Attributes["identity"], nil
				},
				// Action switches (Close/Reopen/…) and System.Object-backed attributes
				// are best-effort and do not round-trip; ignore them in the comparison.
				ImportStateVerifyIgnore: []string{
					"add_or_update_sources", "close", "reopen", "remove_sources",
					"case_type", "secondary_case_type", "source_case_type", "sources",
				},
			},
			{ // in-place update
				Config: testAccComplianceCaseConfig(name, "Acc updated"),
				Check:  resource.TestCheckResourceAttr(resourceName, "description", "Acc updated"),
			},
		},
	})
}

func testAccComplianceCaseConfig(name, description string) string {
	return fmt.Sprintf(`
resource "scc_compliance_case" "test" {
  name        = %[1]q
  description = %[2]q
}

data "scc_compliance_case" "by_identity" {
  identity = scc_compliance_case.test.identity
}

data "scc_compliance_cases" "all" {
  depends_on = [scc_compliance_case.test]
}
`, name, description)
}
