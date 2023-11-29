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
	"PackageCopyrightText: NOASSERTION\n" +
	"\n" +
	"##### Package: test-baselayout3\n" +
	"\n" +
	"PackageName: test-baselayout3\n" +
	"SPDXID: SPDXRef-Package-apk-test-baselayout3\n" +
	"PackageVersion: 1.1.1-r3\n" +
	"PackageDownloadLocation: NOASSERTION\n" +
	"FilesAnalyzed: false\n" +
	"PackageLicenseConcluded: LGPL-2.1-only AND MIT AND BSD-2-Clause\n" +
	"PackageLicenseDeclared: LGPL-2.1-only AND MIT AND BSD-2-Clause\n" +
	"PackageCopyrightText: NOASSERTION\n")

func TestProcessSPDXJsonMediaType(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "bom.json"))
	if err != nil {
		t.Fatalf("error reading %s", filepath.Join("testdata", "bom.json"))
	}
	vr, err := processSpdxJSONMediaType("test", b, nil, nil)
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
	_, err = processSpdxJSONMediaType("test", b, nil, nil)
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

	violation2 := utils.PackageLicense{
		PackageName:    "test-baselayout3",
		PackageLicense: "LGPL-2.1-only AND MIT AND BSD-2-Clause",
		PackageVersion: "1.1.1-r3",
	}

	baselayoutr2 := utils.PackageInfo{
		Name:    "test-baselayout",
		Version: "1.1.1-r2",
	}

	spdxDoc, _ := utils.BlobToSPDX(spdxTestBytes)

	cases := []struct {
		description               string
		disallowedLicenses        []string
		disallowedPackages        []utils.PackageInfo
		expectedLicenseViolations []utils.PackageLicense
		expectedPackageViolations []utils.PackageLicense
		enabled                   bool
	}{
		{
			description:               "package and license violation found",
			disallowedLicenses:        []string{"LicenseRef-Artistic", "GPL-2.0-only"},
			disallowedPackages:        []utils.PackageInfo{baselayout},
			expectedLicenseViolations: []utils.PackageLicense{violation},
			expectedPackageViolations: []utils.PackageLicense{violation},
		},
		{
			description:               "license violation with simple license expressions",
			disallowedLicenses:        []string{"LGPL-2.1-only"},
			disallowedPackages:        []utils.PackageInfo{},
			expectedLicenseViolations: []utils.PackageLicense{violation2},
			expectedPackageViolations: []utils.PackageLicense{},
		},
		{
			description:               "license violation case insensitive",
			disallowedLicenses:        []string{"lgpl-2.1-only"},
			disallowedPackages:        []utils.PackageInfo{},
			expectedLicenseViolations: []utils.PackageLicense{violation2},
			expectedPackageViolations: []utils.PackageLicense{},
		},
		{
			description:               "package violation not found",
			disallowedLicenses:        []string{},
			disallowedPackages:        []utils.PackageInfo{baselayoutr2},
			expectedLicenseViolations: []utils.PackageLicense{},
			expectedPackageViolations: []utils.PackageLicense{},
			enabled:                   true,
		},
		{
			description:               "license violation not found",
			disallowedLicenses:        []string{"GPL-3.0-only"},
			disallowedPackages:        []utils.PackageInfo{},
			expectedLicenseViolations: []utils.PackageLicense{},
			expectedPackageViolations: []utils.PackageLicense{},
		},
	}

	for _, tc := range cases {
		t.Run("test scenario", func(t *testing.T) {

			packageViolation, licensesViolation, _ := getViolations(spdxDoc, tc.disallowedLicenses, tc.disallowedPackages)

			if len(tc.expectedPackageViolations) != len(packageViolation) {
				t.Fatalf("Test %s failed. Expected len of expectedPackageViolations %v, got: %v", tc.description, len(tc.expectedPackageViolations), len(packageViolation))
			}

			if len(tc.expectedLicenseViolations) != len(licensesViolation) {
				t.Fatalf("Test %s failed. Expected len of expectedLicenseViolations %v, got: %v", tc.description, len(tc.expectedPackageViolations), len(packageViolation))
			}

			// check if packageViolation equals expectedPackageViolations
			for i, packageInfo := range packageViolation {
				if packageInfo.PackageName != tc.expectedPackageViolations[i].PackageName {
					t.Fatalf("Test %s failed. Expected: %s, got: %s", tc.description, packageInfo.PackageName, tc.expectedPackageViolations[i].PackageName)
				}
				if packageInfo.PackageVersion != tc.expectedPackageViolations[i].PackageVersion {
					t.Fatalf("Test %s Failed. expected: %s, got: %s", tc.description, packageInfo.PackageVersion, tc.expectedPackageViolations[i].PackageVersion)
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
}
