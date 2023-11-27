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

	baselayout := utils.PackageInfo{
		Name:    "test-baselayout",
		Version: "1.1.1-r1",
	}

	violation := utils.PackageLicense{
		PackageName:    "test-baselayout",
		PackageLicense: "GPL-2.0-only",
		PackageVersion: "1.1.1-r1",
	}

	spdxDoc, _ := utils.BlobToSPDX(spdxTestBytes)

	cases := []struct {
		description               string
		disallowedLicenses        []string
		disallowedPackages        []utils.PackageInfo
		expectedLicenseViolations []utils.PackageLicense
		expectedPackageViolations []utils.PackageLicense
	}{
		{
			description:               "package violation found",
			disallowedLicenses:        []string{"LicenseRef-Artistic", "GPL-2.0-only"},
			disallowedPackages:        []utils.PackageInfo{baselayout},
			expectedLicenseViolations: []utils.PackageLicense{violation},
			expectedPackageViolations: []utils.PackageLicense{violation},
		},
	}

	for _, tc := range cases {
		t.Run("test scenario", func(t *testing.T) {
			packageViolation, licensesViolation, _ := getViolations(spdxDoc, tc.disallowedLicenses, tc.disallowedPackages)

			// check if packageViolation equals expectedPackageViolations
			for i, packageInfo := range packageViolation {
				if packageInfo.PackageName != tc.expectedPackageViolations[i].PackageName {
					t.Fatalf("expected: %s, got: %s", packageInfo.PackageName, tc.expectedPackageViolations[i].PackageName)
				}
				if packageInfo.PackageVersion != tc.expectedPackageViolations[i].PackageVersion {
					t.Fatalf("expected: %s, got: %s", packageInfo.PackageVersion, tc.expectedPackageViolations[i].PackageVersion)
				}
			}

			// check if licensesViolation equals expectedLicenseViolations
			for i, packageInfo := range licensesViolation {
				if packageInfo.PackageName != tc.expectedLicenseViolations[i].PackageName {
					t.Fatalf("expected: %s, got: %s", packageInfo.PackageName, tc.expectedLicenseViolations[i].PackageName)
				}
				if packageInfo.PackageVersion != tc.expectedLicenseViolations[i].PackageVersion {
					t.Fatalf("expected: %s, got: %s", packageInfo.PackageVersion, tc.expectedLicenseViolations[i].PackageVersion)
				}
				if packageInfo.PackageLicense != tc.expectedLicenseViolations[i].PackageLicense {
					t.Fatalf("expected: %s, got: %s", packageInfo.PackageLicense, tc.expectedLicenseViolations[i].PackageLicense)
				}
			}

		})
	}

	// test scenarios:
	// packages
	// 1. found
	// 2. not found
	// 3. same package name but different versions, found and not found

	// license
	// 1. found
	// 2. not
	// 3. try a lower case since License is not case sensitive
	// 3. try a non basic license experession
}
