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
	"github.com/deislabs/ratify/plugins/verifier/sbom/utils"

	"github.com/spdx/tools-golang/spdx"

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
	skel.PluginMain("sbom", "2.0.0alpha", VerifyReference, []string{"1.0.0", "2.0.0alpha"})
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

func getViolations(spdxDoc *spdx.Document, disallowedLicenses []string, disallowedPackages []utils.PackageInfo) ([]utils.PackageLicense, []utils.PackageLicense, error) {

	packageLicenses := utils.GetPackageLicenses(*spdxDoc)
	//licenseMap := utils.LoadLicensesMap(disallowedLicenses)
	packageMap := utils.LoadPackagesMap(disallowedPackages)

	// detect violation
	licenseViolation, packageViolation := utils.FilterDisallowedPackages(packageLicenses, disallowedLicenses, packageMap)
	return packageViolation, licenseViolation, nil
}

func processSpdxJSONMediaType(name string, refBlob []byte) (*verifier.VerifierResult, error) {
	var err error

	spdxDoc, err := utils.BlobToSPDX(refBlob)
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
