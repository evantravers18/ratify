/*
Copyright The Ratify Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/deislabs/ratify/plugins/verifier/sbom/utils"
)

func TestProcessSPDXJsonMediaType(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "bom.json"))
	if err != nil {
		t.Fatalf("error reading %s", filepath.Join("testdata", "bom.json"))
	}
	vr, err := processSpdxJSONMediaType("test", b)
	if err != nil {
		t.Fatalf("expected to process spdx json file: %s", filepath.Join("testdata", "bom.json"))
	}
	if !vr.IsSuccess {
		t.Fatalf("expected to successfully verify schema")
	}
}

func TestProcessInvalidSPDXJsonMediaType(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "invalid-bom.json"))
	if err != nil {
		t.Fatalf("error reading %s", filepath.Join("testdata", "invalid-bom.json"))
	}
	_, err = processSpdxJSONMediaType("test", b)
	if err == nil {
		t.Fatalf("expected to have an error processing spdx json file: %s", filepath.Join("testdata", "bom.json"))
	}
}

func TestFormatPackageLicense(t *testing.T) {
	bash := utils.PackageLicense{
		PackageName:    "bash",
		PackageLicense: "License",
		PackageVersion: "4.4.18-2ubuntu1.2",
	}

	testdata := []utils.PackageLicense{bash}

	result :=
		formatPackageLicense(testdata)
	if result == "nil" {
		t.Fatalf("expected to have an error processing spdx json file: %s", filepath.Join("testdata", "bom.json"))
	}
}

func TestGetViolations(t *testing.T) {

	var spdxTestBytes = []byte("" +
		"SPDXVersion: SPDX-2.2\n" +
		"DataLicense: CC0-1.0\n" +
		"SPDXID: SPDXRef-DOCUMENT\n" +
		"DocumentName: localhost-5000/test-v1\n" +
		"DocumentNamespace: localhost-5000/test-v1-c0e2605b-0d32-45e2-9ed3-530611f8798e" +
		"\n" +
		"LicenseListVersion: 3.15\n" +
		"Creator: Organization: Test\n" +
		"Creator: Tool: test-0.0.0\n" +
		"Created: 2021-12-17T20:24:36Z\n" +
		"\n" +
		"##### Package: test-baselayout\n" +
		"\n" +
		"PackageName: test-baselayout\n" +
		"SPDXID: SPDXRef-Package-apk-test-baselayout\n" +
		"PackageVersion: 1.1.1-r1\n" +
		"PackageDownloadLocation: NOASSERTION\n" +
		"FilesAnalyzed: false\n" +
		"PackageLicenseConcluded: GPL-2.0-only\n" +
		"PackageLicenseDeclared: GPL-2.0-only\n" +
		"PackageCopyrightText: NOASSERTION\n")

	bash := utils.PackageInfo{
		Name:    "bash",
		Version: "4.4.18-2ubuntu1.2",
	}

	// define disallowed package and disallowed license
	var disallowedLicenses []string = []string{"LicenseRef-Artistic", "GPL-2.0-only"}
	var disallowedPackages []utils.PackageInfo = []utils.PackageInfo{bash}

	spdxDoc, _ := utils.BlobToSPDX(spdxTestBytes)
	packageViolation, licensesViolation, _ := getViolations(spdxDoc, disallowedLicenses, disallowedPackages)

	if len(packageViolation) != 0 {
		t.Fatalf("expected: %s, got: %s", packageViolation, licensesViolation)
	}
	if len(disallowedLicenses) == 0 {
		t.Fatalf("expected: %s, got: %s", packageViolation, licensesViolation)
	}

	// test scenarios:
	// packages
	// 1. found
	// 2. not found
	// 3. same package name but different versions, found and not found

	// license
	// 1. found exact match
	// 2. found part of expression
	// 3. when there is AND AND situation, OR situation
	// 3. not found
}
