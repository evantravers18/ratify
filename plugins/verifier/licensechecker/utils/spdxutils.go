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

func BlobToSPDX(bytes []byte) (*spdx.Document, error) {
	raw := string(bytes)
	reader := strings.NewReader(raw)
	return tagvalue.Read(reader)
}

// return the array of license fom a license expression
func GetLicensesFromExpression(licenseExpression string) []string {
	var result []string
	licenses := strings.Split(licenseExpression, "AND")
	for i := range licenses {
		license := strings.TrimSpace(licenses[i])
		if license != "" {
			result = append(result, license)
		}
	}
	return result
}

func GetPackages(doc spdx.Document) map[Package]struct{} {
	output := map[Package]struct{}{}
	for _, p := range doc.Packages {

		temp := Package{
			PackageName:    p.PackageName,
			PackageVersion: p.PackageVersion,
		}
		output[temp] = struct{}{}

	}
	return output
}

func GetPackageLicenses(doc spdx.Document) []PackageLicense {
	output := []PackageLicense{}
	for _, p := range doc.Packages {

		// TODO: change to a list of license, separate on AND
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

func LoadPackagesMap(packages []Package) map[Package]struct{} {
	output := map[Package]struct{}{}
	for _, item := range packages {

		output[item] = struct{}{}
	}
	return output
}

func FilterPackageLicenses(packageLicenses []PackageLicense, allowedLicenses map[string]struct{}) []PackageLicense {
	var output []PackageLicense
	for _, packageLicense := range packageLicenses {
		_, ok := allowedLicenses[packageLicense.PackageLicense]
		if !ok {
			output = append(output, packageLicense)
		}
	}
	return output
}

// returns package in violation
func FilterDisallowedPackages(packageLicenses []PackageLicense, disallowedLicense map[string]struct{}, disallowedPackage map[Package]struct{}) ([]PackageLicense, []PackageLicense) {
	var violationLicense []PackageLicense
	var violationPackage []PackageLicense

	for _, packageLicense := range packageLicenses {
		for _, license := range packageLicense.PackageLicenses {
			// license check
			_, ok := disallowedLicense[license]
			if ok {
				violationLicense = append(violationLicense, packageLicense)
			}
		}

		// package check
		current := Package{
			PackageName:    packageLicense.PackageName,
			PackageVersion: packageLicense.PackageVersion,
		}
		_, ok := disallowedPackage[current]
		if ok {
			violationPackage = append(violationPackage, packageLicense)
		}
	}
	return violationLicense, violationPackage
}
