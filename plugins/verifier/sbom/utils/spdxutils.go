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

// Get the packageLicense array from spdxDoc
func GetPackageLicenses(doc spdx.Document) []PackageLicense {
	output := []PackageLicense{}
	for _, p := range doc.Packages {
		output = append(output, PackageLicense{
			PackageName:    p.PackageName,
			PackageVersion: p.PackageVersion,
			PackageLicense: p.PackageLicenseConcluded,
		})
	}
	return output
}

// load packageInfo into a map for easier existence check
func LoadPackagesMap(packages []PackageInfo) map[PackageInfo]struct{} {
	output := map[PackageInfo]struct{}{}
	for _, item := range packages {
		output[item] = struct{}{}
	}
	return output
}
