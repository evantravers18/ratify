package manager

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/deislabs/ratify/experimental/proto/v2/verifier"
	cs "github.com/deislabs/ratify/experimental/ratify/proto/v2/certstore"
	"github.com/sirupsen/logrus"
)

var (
	tls      = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	certFile = flag.String("cert_file", "", "The TLS cert file")
	keyFile  = flag.String("key_file", "", "The TLS key file")
	port     = flag.Int("port", 50051, "The server port")
)

var (
	//tls                = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	caFile             = flag.String("ca_file", "", "The file containing the CA root cert file")
	serverAddr         = flag.String("addr", "localhost:50051", "The server address in the format of host:port")
	serverHostOverride = flag.String("server_host_override", "x.test.example.com", "The server name used to verify the hostname returned by the TLS handshake")
)

func newServer() pb.VerifierPluginServer {
	s := &VerifierServer{}
	return s
}

func StartGRPCServer() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	/*if *tls {
		if *certFile == "" {
			*certFile = data.Path("x509/server_cert.pem")
		}
		if *keyFile == "" {
			*keyFile = data.Path("x509/server_key.pem")
		}
		creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("Failed to generate credentials: %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}*/
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterVerifierPluginServer(grpcServer, newServer())
	grpcServer.Serve(lis)
}

func HashicorpDriver() {
	// We don't want to see the plugin logs.
	//log.SetOutput(ioutil.Discard)

	// We're a host. Start by launching the plugin process.
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: cs.Handshake,
		Plugins:         cs.PluginMap,
		Cmd:             exec.Command("sh", "-c", "/home/azureuser/repo/susanFork/ratify/pkg/certificateprovider/kv-go-grpc"),
		AllowedProtocols: []plugin.Protocol{
			plugin.ProtocolNetRPC, plugin.ProtocolGRPC},
	})
	defer client.Kill()

	// Connect via RPC
	rpcClient, err := client.Client()
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}

	// Request the plugin
	raw, err := rpcClient.Dispense("kv_grpc")
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}

	// We should have a KV store now! This feels like a normal interface
	// implementation but is in fact over an RPC connection.
	kv := raw.(cs.AKV)

	attrib := map[string]string{}
	attrib["keyvaultName"] = "notarycerts"

	result, err := kv.Get(attrib)
	if err != nil {
		fmt.Println("Error:", err.Error())
		os.Exit(1)
	}

	fmt.Println(string(result))

}

func StartClientAndMakeReq() {
	var opts []grpc.DialOption

	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))

	conn, err := grpc.Dial(*serverAddr, opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()

	client := pb.NewVerifierPluginClient(conn)
	sampleRequest := pb.VerifyReferenceRequest{
		Subject: "hellorequest",
	}
	sample, err := client.VerifyReference(context.Background(), &sampleRequest)
	logrus.Info("client returned %v", sample.Subject)

}
