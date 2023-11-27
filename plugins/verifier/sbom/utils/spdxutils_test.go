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

package utils

import (
	"testing"
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

func TestBlobToSPDX(t *testing.T) {
	spdxDoc, err := BlobToSPDX(spdxTestBytes)
	if err != nil {
		t.Fatalf("could not parse SPDX doc from bytes")
	}
	expected := "localhost-5000/test-v1"
	result := spdxDoc.DocumentName
	if expected != result {
		t.Fatalf("expected: %s, got: %s", expected, result)
	}
	expectedLen := 1
	resultLen := len(spdxDoc.Packages)
	if expectedLen != resultLen {
		t.Fatalf("expected: %d, got: %d", expectedLen, resultLen)
	}
}

func TestGetPackageLicenses(t *testing.T) {
	spdxDoc, err := BlobToSPDX(spdxTestBytes)
	if err != nil {
		t.Fatalf("could not parse SPDX doc from bytes")
	}
	expected := "GPL-2.0-only"
	result := GetPackageLicenses(*spdxDoc)
	if len(result) != 1 {
		t.Fatalf("no packages parsed, expected 1")
	}
	if result[0].PackageLicense != expected {
		t.Fatalf("expected: %s, got: %s", expected, result[0].PackageLicense)
	}
}

func TestLoadAllowedLicenses(t *testing.T) {
	license := "GPL-2.0-only"
	licenses := LoadLicensesMap([]string{license})
	_, ok := licenses[license]
	if !ok {
		t.Fatalf("expected license but not present")
	}
}

func TestGetLicensesFromExpression(t *testing.T) {
	cases := []struct {
		description    string
		license        string
		expectedResult []string
	}{
		{
			description:    "Expression with LicenseRef-AND",
			license:        "BSD-2-Clause AND LicenseRef-AND AND BSD-3-Clause",
			expectedResult: []string{"BSD-2-Clause", "LicenseRef-", "BSD-3-Clause"},
		},
		{
			description:    "single license",
			license:        "GPL-2.0-only",
			expectedResult: []string{"GPL-2.0-only"},
		},
		{
			description:    "Long expression",
			license:        "MIT AND LicenseRef-AND AND BSD-2-Clause AND LicenseRef-AND AND GPL-2.0-or-later",
			expectedResult: []string{"MIT", "LicenseRef-", "BSD-2-Clause", "LicenseRef-", "GPL-2.0-or-later"},
		},
		{
			description:    "OR is treated as AND",
			license:        "MIT OR GPL-2.0-or-later",
			expectedResult: []string{"MIT", "LicenseRef-", "BSD-2-Clause", "LicenseRef-", "GPL-2.0-or-later"},
		},
		{
			description:    "WITH is treated as AND",
			license:        "MIT OR GPL-2.0-or-later",
			expectedResult: []string{"MIT", "LicenseRef-", "BSD-2-Clause", "LicenseRef-", "GPL-2.0-or-later"},
		},
	}

	for _, tc := range cases {
		t.Run("test scenario", func(t *testing.T) {

			result := GetLicensesFromExpression(tc.license)
			if !ArrayEqual(result, tc.expectedResult) {
				t.Fatalf("expected: %v, got: %v", tc.expectedResult, result)
			}
		})
	}

}

func ArrayEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
