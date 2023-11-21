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
	"os"

	"github.com/deislabs/ratify/plugins/verifier/licensechecker/utils"

	"github.com/deislabs/ratify/pkg/common"
	"github.com/deislabs/ratify/pkg/ocispecs"
	"github.com/deislabs/ratify/pkg/referrerstore"
	_ "github.com/deislabs/ratify/pkg/referrerstore/oras"
	"github.com/deislabs/ratify/pkg/verifier"
	"github.com/deislabs/ratify/pkg/verifier/plugin/skel"
)

type PluginConfig struct {
	Name            string   `json:"name"`
	AllowedLicenses []string `json:"allowedLicenses"`
}

type PluginInputConfig struct {
	Config PluginConfig `json:"config"`
}

func main() {
	refBlob, _ := os.ReadFile("/home/azureuser/repo/susanFork/ratify/plugins/verifier/licensechecker/.staging/licensechecker/large.spdx")
	bash := utils.Package{
		PackageName:    "bash",
		PackageVersion: "4.4.18-2ubuntu1.2",
	}

	// define disallowed package and disallowed license
	var disallowedLicenses []string = []string{"LicenseRef-Artistic", "GPL-2.0-only"}
	var disallowedPackages []utils.Package = []utils.Package{bash}

	tempValidate(refBlob, disallowedLicenses, disallowedPackages)
	skel.PluginMain("licensechecker", "1.0.0", VerifyReference, []string{"1.0.0"})
}

func tempValidate(refBlob []byte, disallowedLicenses []string, disallowedPackages []utils.Package) ([]utils.PackageLicense, []utils.PackageLicense, error) {
	// first read from local file

	// parse  spdx or cyclone dx
	spdxDoc, err := utils.BlobToSPDX(refBlob)
	if err != nil {
		return nil, nil, err
	}

	// build the internal data structures
	//packages := utils.GetPackages(*spdxDoc)
	packageLicenses := utils.GetPackageLicenses(*spdxDoc)
	licenseMap := utils.LoadLicensesMap(disallowedLicenses)
	packageMap := utils.LoadPackagesMap(disallowedPackages)

	// detect violation
	licenseViolation, packageViolation := utils.FilterDisallowedPackages(packageLicenses, licenseMap, packageMap)
	//violationLicense := utils.FilterDisallowedLicenses(packageLicenses, licenseMap)
	fmt.Println(packageViolation)
	fmt.Println(licenseViolation)
	return packageViolation, licenseViolation, nil
}

func parseInput(stdin []byte) (*PluginConfig, error) {
	conf := PluginInputConfig{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse stdin for input: %w", err)
	}

	return &conf.Config, nil
}

func VerifyReference(args *skel.CmdArgs, subjectReference common.Reference, descriptor ocispecs.ReferenceDescriptor, store referrerstore.ReferrerStore) (*verifier.VerifierResult, error) {
	input, err := parseInput(args.StdinData)
	if err != nil {
		return nil, err
	}

	allowedLicenses := utils.LoadLicensesMap(input.AllowedLicenses)

	ctx := context.Background()
	referenceManifest, err := store.GetReferenceManifest(ctx, subjectReference, descriptor)
	if err != nil {
		return nil, err
	}

	if len(referenceManifest.Blobs) == 0 {
		return &verifier.VerifierResult{
			Name:      input.Name,
			IsSuccess: false,
			Message:   fmt.Sprintf("License Check FAILED: no blobs found for referrer %s@%s", subjectReference.Path, descriptor.Digest.String()),
		}, nil
	}

	for _, blobDesc := range referenceManifest.Blobs {
		refBlob, err := store.GetBlobContent(ctx, subjectReference, blobDesc.Digest)
		if err != nil {
			return nil, err
		}

		spdxDoc, err := utils.BlobToSPDX(refBlob)
		if err != nil {
			return nil, err
		}

		packageLicenses := utils.GetPackageLicenses(*spdxDoc)
		disallowedLicenses := utils.FilterPackageLicenses(packageLicenses, allowedLicenses)

		if len(disallowedLicenses) > 0 {
			return &verifier.VerifierResult{
				Name:      input.Name,
				IsSuccess: false,
				Message:   fmt.Sprintf("License Check: FAILED. %s", disallowedLicenses),
			}, nil
		}
	}

	return &verifier.VerifierResult{
		Name:      input.Name,
		IsSuccess: true,
		Message:   "License Check: SUCCESS. All packages have allowed licenses",
	}, nil
}
