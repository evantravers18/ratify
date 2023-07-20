// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"strconv"

	"github.com/deislabs/ratify/pkg/certificateprovider"
	_ "github.com/deislabs/ratify/pkg/certificateprovider/azurekeyvault" // register azure keyvault certificate provider

	cs "github.com/deislabs/ratify/experimental/ratify/proto/v2/certstore"
	"github.com/hashicorp/go-plugin"
	"github.com/sirupsen/logrus"
)

// Here is a real implementation of KV that writes to a local file with
// the key name and the contents are the value of the key.
type AKV struct{}

func (AKV) Get(attrib map[string]string) ([]byte, error) {
	logrus.Info("Message from implementation of the plugin, size of attrib", len(attrib))

	providers := certificateprovider.GetCertificateProviders()
	akvProvider := providers["azurekeyvault"]
	str := "akProvider is nil"
	if akvProvider == nil {
		logrus.Info("provider is nil")

	} else {
		results, _, err := akvProvider.GetCertificates(context.Background(), attrib)

		errString := ", error, " + err.Error()

		str = errString + "in the future we should return cert or byte array," + strconv.Itoa(len(results))

	}
	// converting and printing Byte array

	return []byte(str), nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: cs.Handshake,
		Plugins: map[string]plugin.Plugin{
			"kv": &cs.CertStoreGRPCPlugin{Impl: &AKV{}},
		},

		// A non-nil value here enables gRPC serving for this plugin...
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
