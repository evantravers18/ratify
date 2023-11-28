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
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/deislabs/ratify/pkg/common"
	"github.com/deislabs/ratify/pkg/ocispecs"
	"github.com/deislabs/ratify/pkg/referrerstore"
	"github.com/deislabs/ratify/plugins/verifier/sbom/utils"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"

	// This import is required to utilize the oras built-in referrer store
	_ "github.com/deislabs/ratify/pkg/referrerstore/oras"
	"github.com/deislabs/ratify/pkg/verifier"
	"github.com/deislabs/ratify/pkg/verifier/plugin/skel"
)

// PluginConfig describes the configuration of the sbom verifier
type PluginConfig struct {
	Name               string              `json:"name"`
	DisallowedLicenses []string            `json:"disallowedLicenses"`
	DisallowedPackages []utils.PackageInfo `json:"disallowedPackages"`
}

type PluginInputConfig struct {
	Config PluginConfig `json:"config"`
}

const (
	SpdxJSONMediaType string = "application/spdx+json"
)

func main() {
	skel.PluginMain("sbom", "1.1.0-alpha.1", VerifyReference, []string{"1.0.0", "1.1.0-alpha.1"})
}

func parseInput(stdin []byte) (*PluginConfig, error) {
	conf := PluginInputConfig{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse stdin for the input: %w", err)
	}

	return &conf.Config, nil
}

func VerifyReference(args *skel.CmdArgs, subjectReference common.Reference, referenceDescriptor ocispecs.ReferenceDescriptor, referrerStore referrerstore.ReferrerStore) (*verifier.VerifierResult, error) {

	input, err := parseInput(args.StdinData)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	referenceManifest, err := referrerStore.GetReferenceManifest(ctx, subjectReference, referenceDescriptor)
	if err != nil {
		return &verifier.VerifierResult{
			Name:      input.Name,
			IsSuccess: false,
			Message:   fmt.Sprintf("Error fetching reference manifest for subject: %s reference descriptor: %v", subjectReference, referenceDescriptor.Descriptor),
		}, err
	}

	var mediaType string
	for _, blobDesc := range referenceManifest.Blobs {
		mediaType = blobDesc.MediaType

		refBlob, err := referrerStore.GetBlobContent(ctx, subjectReference, blobDesc.Digest)

		if err != nil {
			return &verifier.VerifierResult{
				Name:      input.Name,
				IsSuccess: false,
				Message:   fmt.Sprintf("Error fetching blob for subject: %s digest: %s", subjectReference, blobDesc.Digest),
			}, err
		}

		switch mediaType {
		case SpdxJSONMediaType:
			// TODO support cyclone dx
			spdxDoc, err := utils.BlobToSPDX(refBlob)
			if err != nil {
				return nil, err
			}

			packageViolation, licenseViolation, err := getViolations(spdxDoc, input.DisallowedLicenses, input.DisallowedPackages)
			if err != nil {
				return nil, fmt.Errorf("failed to get SBOM violation %w", err)
			}

			if licenseViolation != nil || packageViolation != nil {
				return &verifier.VerifierResult{
					Name:       input.Name,
					IsSuccess:  false,
					Extensions: blobDesc.Digest,
					Message:    fmt.Sprintf("SBOM validation failed, '%v' packages with license violation,  '%v' package with package violation, packages with license violations %v,  packages with violations %v ", len(licenseViolation), len(packageViolation), formatPackageLicense(licenseViolation), formatPackageLicense(packageViolation)),
				}, err
			}

			return &verifier.VerifierResult{
				Name:       input.Name,
				IsSuccess:  true,
				Extensions: spdxDoc.CreationInfo,
				Message:    "SBOM is good, no violation detected",
			}, err

		default:
		}
	}
	return &verifier.VerifierResult{
		Name:      input.Name,
		IsSuccess: false,
		Message:   fmt.Sprintf("SBOM verifier Unsupported mediaType: %s", mediaType),
	}, nil
}

func formatPackageLicense(packages []utils.PackageLicense) string {
	var result = "["
	for _, p := range packages {
		result = result + fmt.Sprintf("{PackageName: '%v', PackageVersion: '%v', PackageLicense: '%v' },", p.PackageName, p.PackageVersion, p.PackageLicense)
	}
	result += "]"
	return result
}

// getViolations returns the package and license violations based on the deny list
func getViolations(spdxDoc *spdx.Document, disallowedLicenses []string, disallowedPackages []utils.PackageInfo) ([]utils.PackageLicense, []utils.PackageLicense, error) {

	packageLicenses := utils.GetPackageLicenses(*spdxDoc)
	packageMap := utils.LoadPackagesMap(disallowedPackages)

	// detect violation
	licenseViolation, packageViolation := filterDisallowedPackages(packageLicenses, disallowedLicenses, packageMap)
	return packageViolation, licenseViolation, nil
}

func processSpdxJSONMediaType(name string, refBlob []byte) (*verifier.VerifierResult, error) {
	var err error
	var spdxDoc *v2_3.Document
	if spdxDoc, err = utils.BlobToSPDX(refBlob); err == nil {
		return &verifier.VerifierResult{
			Name:       name,
			IsSuccess:  true,
			Extensions: spdxDoc.CreationInfo,
			Message:    "SBOM verification success. The schema is good.",
		}, nil
	}

	return &verifier.VerifierResult{
		Name:      name,
		IsSuccess: false,
		Message:   fmt.Sprintf("SBOM failed to parse: %v", err),
	}, err
}

// iterate through all package info and check against the deny list
// return the violation packages
func filterDisallowedPackages(packageLicenses []utils.PackageLicense, disallowedLicense []string, disallowedPackage map[utils.PackageInfo]struct{}) ([]utils.PackageLicense, []utils.PackageLicense) {
	var violationLicense []utils.PackageLicense
	var violationPackage []utils.PackageLicense

	for _, packageInfo := range packageLicenses {
		// if license contains disallowed, add to violation
		for _, disallowed := range disallowedLicense {
			license := packageInfo.PackageLicense

			if license != "" && strings.Contains(strings.ToLower(license), strings.ToLower(disallowed)) {
				violationLicense = append(violationLicense, packageInfo)
			}
		}

		// package check
		current := utils.PackageInfo{
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
