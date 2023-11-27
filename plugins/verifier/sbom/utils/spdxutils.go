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
	"strings"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/tagvalue"
)

var AndLicense = "AND"
var OrLicense = "OR"

// returns a spdxDocument and error
func BlobToSPDX(bytes []byte) (*spdx.Document, error) {
	raw := string(bytes)
	reader := strings.NewReader(raw)
	return tagvalue.Read(reader)
}

// return the array of license fom a license expression, ONLY , AND and OR is supported
// We don't support ()
func GetLicensesFromExpression(licenseExpression string) []string {
	var result []string

	// https://spdx.github.io/spdx-spec/v2-draft/SPDX-license-expressions/#d3-simple-license-expressions
	// more examples at https://github.com/spdx/spdx-examples/blob/master/software/example7/spdx2.2/example7-golang.spdx.json

	// replace OR with AND , since we can't predict which license can be used
	licenseExpression = strings.Replace(licenseExpression, OrLicense, AndLicense, -1)

	// replace OR with AND
	licenseExpression = strings.Replace(licenseExpression, OrLicense, AndLicense, -1)

	licenses := strings.Split(licenseExpression, AndLicense)
	for i := range licenses {
		license := strings.TrimSpace(licenses[i])
		if license != "" {
			result = append(result, license)
		}
	}
	return result
}

// Create a package set from spdxDoc
func GetPackages(doc spdx.Document) map[PackageInfo]struct{} {
	output := map[PackageInfo]struct{}{}
	for _, p := range doc.Packages {

		temp := PackageInfo{
			Name:    p.PackageName,
			Version: p.PackageVersion,
		}
		output[temp] = struct{}{}

	}
	return output
}

// Get the packageLicense array from spdxDoc, TODO, why do we have both license and licenses?
func GetPackageLicenses(doc spdx.Document) []PackageLicense {
	output := []PackageLicense{}
	for _, p := range doc.Packages {
		output = append(output, PackageLicense{
			PackageName:     p.PackageName,
			PackageVersion:  p.PackageVersion,
			PackageLicense:  p.PackageLicenseConcluded,
			PackageLicenses: GetLicensesFromExpression(p.PackageLicenseConcluded),
		})
	}
	return output
}

func LoadLicensesMap(licenses []string) map[string]struct{} {
	output := map[string]struct{}{}
	for _, license := range licenses {
		output[license] = struct{}{}
	}
	return output
}

func LoadPackagesMap(packages []PackageInfo) map[PackageInfo]struct{} {
	output := map[PackageInfo]struct{}{}
	for _, item := range packages {

		output[item] = struct{}{}
	}
	return output
}

// returns package in violation
func FilterDisallowedPackages(packageLicenses []PackageLicense, disallowedLicense []string, disallowedPackage map[PackageInfo]struct{}) ([]PackageLicense, []PackageLicense) {
	var violationLicense []PackageLicense
	var violationPackage []PackageLicense

	for _, packageInfo := range packageLicenses {
		for _, disallowed := range disallowedLicense {
			license := packageInfo.PackageLicense
			// if license contains disallowed, add to violation
			if license != "" && strings.Contains(strings.ToLower(license), strings.ToLower(disallowed)) {
				violationLicense = append(violationLicense, packageInfo)
			}
		}

		// package check
		current := PackageInfo{
			Name:    packageInfo.PackageName,
			Version: packageInfo.PackageVersion,
		}
		_, ok := disallowedPackage[current]
		if ok {
			violationPackage = append(violationPackage, packageInfo)
		}
	}
	return violationLicense, violationPackage
}
