// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"strconv"

	cs "github.com/deislabs/ratify/experimental/ratify/proto/v2/certstore"
	"github.com/deislabs/ratify/pkg/certificateprovider"
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

	results, _, _ := akvProvider.GetCertificates(context.Background(), attrib)

	str := "in the future we should return cert or byte array" + strconv.Itoa(len(results))
	// converting and printing Byte array

	return []byte(str), nil
}

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: cs.Handshake,
		Plugins: map[string]plugin.Plugin{
			"kv": &cs.AKVCertStoreGRPCPlugin{Impl: &AKV{}},
		},

		// A non-nil value here enables gRPC serving for this plugin...
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
