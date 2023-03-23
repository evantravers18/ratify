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

package notaryv2

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/deislabs/ratify/pkg/controllers"
	"github.com/deislabs/ratify/pkg/utils"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/sirupsen/logrus"
)

type trustStore struct {
	certPaths  []string
	certStores map[string][]string
}

// trustStore implements GetCertificates API of X509TrustStore interface: [https://pkg.go.dev/github.com/notaryproject/notation-go@v1.0.0-rc.3/verifier/truststore#X509TrustStore]
// Note: this api gets invoked when Ratify calls verify API, so the certificates
// will be loaded for each signature verification.
// And this API must follow the Notation Trust Store spec: https://github.com/notaryproject/notaryproject/blob/main/specs/trust-store-trust-policy.md#trust-store
func (s trustStore) GetCertificates(ctx context.Context, storeType truststore.Type, namedStore string) ([]*x509.Certificate, error) {
	certs, err := s.getCertificatesInternal(ctx, storeType, namedStore, controllers.GetCertificatesMap())
	if err != nil {
		return nil, err
	}
	return s.filterValidCerts(certs)
}

func (s trustStore) getCertificatesInternal(ctx context.Context, storeType truststore.Type, namedStore string, certificatesMap map[string][]*x509.Certificate) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, 0)

	// certs configured for this namedStore overrides cert path
	if certGroup := s.certStores[namedStore]; len(certGroup) > 0 {
		for _, certStore := range certGroup {
			result := certificatesMap[certStore]
			if len(result) == 0 {
				logrus.Warnf("no certificate fetched for certStore %+v", certStore)
			}
			certs = append(certs, result...)
		}
		if len(certs) == 0 {
			return certs, fmt.Errorf("unable to fetch certificates for namedStore: %+v", namedStore)
		}
	} else {
		for _, path := range s.certPaths {
			bundledCerts, err := utils.GetCertificatesFromPath(path)
			if err != nil {
				return nil, err
			}
			certs = append(certs, bundledCerts...)
		}
	}

	return certs, nil
}

// filterValidCerts keeps CA certificates and self-signed certs.
func (s trustStore) filterValidCerts(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	filteredCerts := make([]*x509.Certificate, 0)
	for _, cert := range certs {
		if !cert.IsCA {
			// check if it's a self-signed certificate.
			if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
				continue
			}
		}
		filteredCerts = append(filteredCerts, cert)
	}
	if len(filteredCerts) == 0 {
		return nil, errors.New("valid certificates must be provided, only CA certificates or self-signed signing certificates are supported")
	}
	return filteredCerts, nil
}
