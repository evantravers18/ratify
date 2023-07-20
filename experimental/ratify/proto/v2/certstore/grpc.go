package certstore

import (
	"context"
)

// GRPCClient is an implementation of KV that talks over RPC.
type GRPCClient struct{ client CertStorePluginClient }

func (m *GRPCClient) Get(attrib map[string]string) ([]byte, error) {

	request := []*GetRequest_AttributeMapEntry{}
	for key, value := range attrib {
		entry := &GetRequest_AttributeMapEntry{
			Key:   key,
			Value: value,
		}
		request = append(request, entry)
	}

	resp, err := m.client.Get(context.Background(), &GetRequest{
		Attrib: request,
	})
	if err != nil {
		return nil, err
	}

	return resp.Value, nil
}

// Here is the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	// This is the real implementation
	Impl CertStore
}

func (m *GRPCServer) Get(
	ctx context.Context,
	req *GetRequest) (*GetResponse, error) {

	attrib := map[string]string{}
	for _, entry := range req.Attrib {
		attrib[entry.Key] = entry.Value
	}

	v, err := m.Impl.Get(attrib)
	return &GetResponse{Value: v}, err
}
