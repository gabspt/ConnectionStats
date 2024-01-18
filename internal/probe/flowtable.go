package probe

import (
	"log"
	"net/netip"
	"sync"
	"time"
)

type FlowTable struct {
	Ticker *time.Ticker
	sync.Map
}

type Connection struct {
	Protocol    string
	L_ip        netip.Addr
	R_ip        netip.Addr
	L_Port      uint16
	R_Port      uint16
	Packets_in  uint32
	Packets_out uint32
	Ts_start    uint64
	Ts_current  uint64
	Bytes_in    uint64
	Bytes_out   uint64
}

// NewFlowTable Constructs a new FlowTable
func NewFlowTable() *FlowTable {
	return &FlowTable{Ticker: time.NewTicker(time.Second * 10)}
}

// delete deletes connection hash and its data from the FlowTable
func (table *FlowTable) Remove(key any) {
	_, found := table.Load(key)

	if found {
		// log.Printf("Removing hash %v from flow table", hash)
		table.Delete(key)
	} else {
		log.Printf("hash %v is not in flow table", key)
	}
}

func (table *FlowTable) CountActiveConns() {
	counter := 0
	table.Range(func(hash, value interface{}) bool {
		counter++
		return true
	})
	log.Printf("There are %v active connections", counter)
}

var ipProtoNums = map[uint8]string{
	6:  "TCP",
	17: "UDP",
}

type IPStruct struct {
	In6U struct {
		U6Addr8 [16]uint8
	}
}

func convertToNetIPAddr(ipStruct IPStruct) (netip.Addr, bool) {
	b := make([]byte, 16)
	for i, v := range ipStruct.In6U.U6Addr8 {
		b[i] = byte(v)
	}
	addr, ok := netip.AddrFromSlice(b)
	return addr, ok
}

func (table *FlowTable) GetConnList() []Connection {
	var connlist []Connection
	table.Range(func(key, value interface{}) bool {

		fid, okid := key.(probeFlowId)
		fm, okm := value.(probeFlowMetrics)

		if okid && okm {

			protoc, ok := ipProtoNums[fid.Protocol]
			if !ok {
				log.Print("Failed fetching protocol number: ", fid.Protocol)
			}
			lip, ok := convertToNetIPAddr(fid.L_ip)
			if !ok {
				log.Print("Failed converting IP address: ", fid.L_ip)
			}
			rip, ok := convertToNetIPAddr(fid.R_ip)
			if !ok {
				log.Print("Failed converting IP address: ", fid.R_ip)
			}

			connection := Connection{
				Protocol:    protoc,
				L_ip:        lip,
				R_ip:        rip,
				L_Port:      fid.L_port,
				R_Port:      fid.R_port,
				Packets_in:  fm.PacketsIn,
				Packets_out: fm.PacketsOut,
				Ts_start:    fm.TsStart,
				Ts_current:  fm.TsCurrent,
				Bytes_in:    fm.BytesIn,
				Bytes_out:   fm.BytesOut,
			}

			connlist = append(connlist, connection)
		}
		return true
	})
	return connlist
}
