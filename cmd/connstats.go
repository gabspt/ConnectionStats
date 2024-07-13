package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/gabspt/ConnectionStats/connstatsprotobuf"
	"github.com/gabspt/ConnectionStats/internal/probe"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
)

var (
	ifaceFlag          = flag.String("i", "enp0s8", "interface to attach the probe to") //enp0s3
	port               = flag.Int("port", 50051, "The grpc server port")
	timeAgrupationFlag = flag.Uint64("t", 5, "how often to evict the flow statistics from the kernel (in seconds)")
	ft                 = probe.NewFlowTable()
)

// signalHandler catches SIGINT and SIGTERM then exits the program
func signalHandler(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nCaught SIGINT... Exiting")
		cancel()
	}()
}

// displayInterfaces displays all available network interfaces
func displayInterfaces() {
	interfaces, err := net.Interfaces()

	if err != nil {
		log.Fatal("Failed fetching network interfaces")
		return
	}

	for i, iface := range interfaces {
		fmt.Printf("%d %s\n", i, iface.Name)
	}
	os.Exit(1)
}

// server is used to implement ConnStatServer.
type server struct {
	pb.UnimplementedStatsServiceServer
}

func (s *server) CollectStats(ctx context.Context, req *pb.StatsRequest) (*pb.StatsReply, error) {
	log.Printf("Received request")
	response := &pb.StatsReply{}

	connlist := ft.GetConnList()
	for _, conn := range connlist {
		connMsg := &pb.ConnectionStat{
			Protocol: conn.Protocol,
			LIp:      conn.L_ip.String(),
			RIp:      conn.R_ip.String(),
			LPort:    uint32(conn.L_Port),
			RPort:    uint32(conn.R_Port),
			Inpps:    conn.Inpps,
			Outpps:   conn.Outpps,
			Inbpp:    conn.Inbpp,
			Outbpp:   conn.Outbpp,
			Inboutb:  conn.Inboutb,
			Inpoutp:  conn.Inpoutp,
		}
		//fmt.Printf("connMsg %v\n", connMsg)
		response.Connstat = append(response.Connstat, connMsg)
	}
	//fmt.Printf("%v\n", response)
	return response, nil
}

func main() {
	flag.Parse()

	//Configure probe's network interface
	iface, errint := netlink.LinkByName(*ifaceFlag)
	if errint != nil {
		log.Printf("Could not find interface %v: %v", *ifaceFlag, errint)
		displayInterfaces()
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	signalHandler(cancel)

	//Configure gRPC server
	go func() {
		lis, errlis := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if errlis != nil {
			log.Fatalf("failed to listen: %v", errlis)
		}
		s := grpc.NewServer()
		pb.RegisterStatsServiceServer(s, &server{})
		log.Printf("server listening at %v", lis.Addr())
		if errs := s.Serve(lis); errs != nil {
			log.Fatalf("failed to serve: %v", errs)
		}

	}()

	//Run the probe. Pass the context and the network interface
	if err := probe.Run(ctx, iface, ft, *timeAgrupationFlag); err != nil {
		log.Fatalf("Failed running the probe: %v", err)
	}

}
