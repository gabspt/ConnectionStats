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

	//"sync"

	pb "github.com/gabspt/ConnectionStats/connstatsprotobuf"
	"github.com/gabspt/ConnectionStats/internal/flowtable"
	"github.com/gabspt/ConnectionStats/internal/probe"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
)

var (
	ifaceFlag = flag.String("interface", "enp0s3", "interface to attach the probe to") // TODO: change default value to eth0
	port      = flag.Int("port", 50051, "The server port")
	ft        = flowtable.NewFlowTable()
	//ftMutex   sync.RWMutex
	//ctx       context.Context
	//cancel    context.CancelFunc
)

// signalHandler catches SIGINT and SIGTERM then exits the program
func signalHandler(cancel context.CancelFunc) {
	//func signalHandler() {
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

//func createContextAndCancel() (context.Context, context.CancelFunc) {
//	ctx := context.Background()
//	ctx, cancel := context.WithCancel(ctx)
//	return ctx, cancel
//}

// server is used to implement ConnStatServer.
type server struct {
	pb.UnimplementedStatsServiceServer
	//ft *flowtable.FlowTable
}

func (s *server) CollectStats(ctx context.Context, req *pb.StatsRequest) (*pb.StatsReply, error) {
	log.Printf("Received request")
	//fmt.Printf("fmt Print")
	response := &pb.StatsReply{}
	//response.Connstat=ft.GetConnList()
	//connlist := s.ft.GetConnList()
	//ftMutex.RLock()
	//defer ftMutex.RUnlock()

	connlist := ft.GetConnList()
	//fmt.Printf("connlist %v\n", connlist)
	for _, conn := range connlist {
		connMsg := &pb.ConnectionStat{
			Hash:       conn.Hash,
			Proto:      conn.Proto,
			AIp:        conn.AIp.String(),
			BIp:        conn.BIp.String(),
			APort:      uint32(conn.APort),
			BPort:      uint32(conn.BPort),
			PacketsIn:  conn.Packets_in,
			PacketsOut: conn.Packets_out,
			TsIni:      conn.Ts_ini,
			TsFin:      conn.Ts_fin,
			BytesIn:    conn.Bytes_in,
			BytesOut:   conn.Bytes_out,
		}
		//fmt.Printf("connMsg %v\n", connMsg)
		response.Connstat = append(response.Connstat, connMsg)
	}
	//fmt.Printf("%v\n", response)
	return response, nil
}

func main() {
	flag.Parse()

	//ctx, cancel = createContextAndCancel()

	//Configure probe's network interface
	iface, errint := netlink.LinkByName(*ifaceFlag)
	if errint != nil {
		log.Printf("Could not find interface %v: %v", *ifaceFlag, errint)
		displayInterfaces()
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	signalHandler(cancel)
	//signalHandler()

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
		// Signal that the server has finished

	}()

	//Run the probe. Pass the context and the network interface
	if err := probe.Run(ctx, iface, ft); err != nil {
		log.Fatalf("Failed running the probe: %v", err)
	}

}
