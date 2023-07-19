package certstore

import (
	"context"
)

// GRPCClient is an implementation of KV that talks over RPC.
type GRPCClient struct{ client AKVPluginClient }

func (m *GRPCClient) Get(attrib map[string]string) ([]byte, error) {
	test := &GetRequest_AttributeMapEntry{
		Key:   "test",
		Value: "testvalue",
	}

	strSlice := make([]*GetRequest_AttributeMapEntry, 5)
	strSlice = append(strSlice, test)

	resp, err := m.client.Get(context.Background(), &GetRequest{
		Attrib: strSlice,
	})
	if err != nil {
		return nil, err
	}

	return resp.Value, nil
}

// Here is the gRPC server that GRPCClient talks to.
type GRPCServer struct {
	// This is the real implementation
	Impl AKV
}

func (m *GRPCServer) Get(
	ctx context.Context,
	req *GetRequest) (*GetResponse, error) {

	attrib := map[string]string{}
	attrib["keyvaultName"] = "notarycerts"

	//v, err := m.Impl.Get(req.Attrib)
	v, err := m.Impl.Get(attrib)
	return &GetResponse{Value: v}, err
}
