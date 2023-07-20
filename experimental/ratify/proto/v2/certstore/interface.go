package certstore

import (
	"context"

	"google.golang.org/grpc"

	"github.com/hashicorp/go-plugin"
)

// Handshake is a common handshake that is shared by plugin and host.
var Handshake = plugin.HandshakeConfig{
	// This isn't required when using VersionedPlugins
	ProtocolVersion:  1,
	MagicCookieKey:   "BASIC_PLUGIN",
	MagicCookieValue: "hello",
}

// PluginMap is the map of plugins we can dispense.
var PluginMap = map[string]plugin.Plugin{
	"kv_grpc": &CertStoreGRPCPlugin{},
}

// KV is the interface that we're exposing as a plugin.
type CertStore interface {
	//Get(attrib []*GetRequest_AttributeMapEntry) ([]byte, error)
	Get(attrib map[string]string) ([]byte, error)
}

// This is the implementation of plugin.Plugin so we can serve/consume this.
type CertStorePlugin struct {
	// Concrete implementation, written in Go. This is only used for plugins
	// that are written in Go.
	Impl CertStore
}

// This is the implementation of plugin.GRPCPlugin so we can serve/consume this.
type CertStoreGRPCPlugin struct {
	// GRPCPlugin must still implement the Plugin interface
	plugin.Plugin
	// Concrete implementation, written in Go. This is only used for plugins
	// that are written in Go.
	Impl CertStore
}

func (p *CertStoreGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	RegisterCertStorePluginServer(s, &GRPCServer{Impl: p.Impl})
	return nil
}

func (p *CertStoreGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: NewCertStorePluginClient(c)}, nil
}
