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

	"github.com/deislabs/ratify/pkg/common"
	"github.com/deislabs/ratify/pkg/ocispecs"
	"github.com/deislabs/ratify/pkg/referrerstore"
	spdxUtils "github.com/deislabs/ratify/plugins/verifier/sbom/spdxutils"

	// This import is required to utilize the oras built-in referrer store
	_ "github.com/deislabs/ratify/pkg/referrerstore/oras"
	"github.com/deislabs/ratify/pkg/verifier"
	"github.com/deislabs/ratify/pkg/verifier/plugin/skel"
)

// PluginConfig describes the configuration of the sbom verifier
type PluginConfig struct {
	Name               string                  `json:"name"`
	DisallowedLicenses []string                `json:"disallowedLicenses"`
	DisallowedPackages []spdxUtils.PackageInfo `json:"disallowedPackages"`
}

type PluginInputConfig struct {
	Config PluginConfig `json:"config"`
}

const (
	SpdxJSONMediaType string = "application/spdx+json"
)

func main() {
	skel.PluginMain("sbom", "0.alpha", VerifyReference, []string{"1.0.0", "2.0.0alpha"})
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
			// parse  spdx or cyclone dx
			spdxDoc, err := spdxUtils.BlobToSPDX(refBlob)
			if err != nil {
				return nil, err
			}

			//return getViolation(input.Name+string(blobDesc.Digest), refBlob, input.DisallowedLicenses, input.DisallowedPackages)
			packageViolation, licenseViolation, err := getViolations(refBlob, input.DisallowedLicenses, input.DisallowedPackages)
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

func formatPackageLicense(packages []spdxUtils.PackageLicense) string {
	var result = "["
	for _, p := range packages {
		result = result + fmt.Sprintf("{PackageName: '%v', PackageVersion: '%v', PackageLicense: '%v' },", p.PackageName, p.PackageVersion, p.PackageLicense)
	}
	result += "]"
	return result
}

func getViolations(refBlob []byte, disallowedLicenses []string, disallowedPackages []spdxUtils.PackageInfo) ([]spdxUtils.PackageLicense, []spdxUtils.PackageLicense, error) {
	// first read from local file

	// parse  spdx or cyclone dx
	spdxDoc, err := spdxUtils.BlobToSPDX(refBlob)
	if err != nil {
		return nil, nil, err
	}

	// build the internal data structures

	packageLicenses := spdxUtils.GetPackageLicenses(*spdxDoc)
	licenseMap := spdxUtils.LoadLicensesMap(disallowedLicenses)
	packageMap := spdxUtils.LoadPackagesMap(disallowedPackages)

	// detect violation
	licenseViolation, packageViolation := spdxUtils.FilterDisallowedPackages(packageLicenses, licenseMap, packageMap)
	//violationLicense := utils.FilterDisallowedLicenses(packageLicenses, licenseMap)
	return packageViolation, licenseViolation, nil
}
func processSpdxJSONMediaType(name string, refBlob []byte) (*verifier.VerifierResult, error) {
	var err error

	spdxDoc, err := spdxUtils.BlobToSPDX(refBlob)
	if err != nil {
		return &verifier.VerifierResult{
			Name:       name,
			IsSuccess:  true,
			Extensions: "hello",
			Message:    "Blob to spdx was bad",
		}, nil
	}

	return &verifier.VerifierResult{
		Name:       name,
		IsSuccess:  true,
		Extensions: spdxDoc.CreationInfo,
		Message:    fmt.Sprintf("SBOM was good %v", "hi"),
	}, nil
}
