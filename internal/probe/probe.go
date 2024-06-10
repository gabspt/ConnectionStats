package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/gabspt/ConnectionStats/clsact"
	"github.com/gabspt/ConnectionStats/internal/timer"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/connstats.c - -O3  -Wall -Werror -Wno-address-of-packed-member

const tenMegaBytes = 1024 * 1024 * 10      // 10MB
const twentyMegaBytes = tenMegaBytes * 2   // 20MB
const fortyMegaBytes = twentyMegaBytes * 2 // 40MB

const TCP_IDLE_TIME = 300000000000 //300000ms = 5min
const UDP_IDLE_TIME = 200000000000 //200000ms = 3min and 20s
const SINGLETON_TIME = 10000000000 //10000ms = 10s

const EVICTION_TIME = 5                             // 5s time to evict entries from the flowstracker map in seconds
const EVICTION_TIME_NS = EVICTION_TIME * 1000000000 // Convert EVICTION_TIME to nanoseconds

type probe struct {
	iface      netlink.Link
	handle     *netlink.Handle
	qdisc      *clsact.ClsAct
	bpfObjects *probeObjects
	filters    []*netlink.BpfFilter
}

type Flowrecord struct {
	fid probeFlowId
	fm  probeFlowMetrics
}

func setRlimit() error {
	log.Printf("Setting rlimit - soft: %v, hard: %v", twentyMegaBytes, fortyMegaBytes)

	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: tenMegaBytes,
		Max: twentyMegaBytes,
	})
}

func (p *probe) loadObjects() error {
	log.Printf("Loading probe object to kernel")

	objs := probeObjects{}

	if err := loadProbeObjects(&objs, nil); err != nil {
		return err
	}

	p.bpfObjects = &objs

	return nil
}

func (p *probe) createQdisc() error {
	log.Printf("Creating qdisc")

	p.qdisc = clsact.NewClsAct(&netlink.QdiscAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	})

	if err := p.handle.QdiscAdd(p.qdisc); err != nil {
		if err := p.handle.QdiscReplace(p.qdisc); err != nil {
			return err
		}
	}

	return nil
}

func (p *probe) createFilters() error {
	log.Printf("Creating qdisc filters")

	addFilterin := func(attrs netlink.FilterAttrs) {
		p.filters = append(p.filters, &netlink.BpfFilter{
			FilterAttrs:  attrs,
			Fd:           p.bpfObjects.probePrograms.Connstatsin.FD(),
			DirectAction: true,
		})
	}
	addFilterout := func(attrs netlink.FilterAttrs) {
		p.filters = append(p.filters, &netlink.BpfFilter{
			FilterAttrs:  attrs,
			Fd:           p.bpfObjects.probePrograms.Connstatsout.FD(),
			DirectAction: true,
		})
	}

	addFilterin(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Protocol:  unix.ETH_P_IP,
	})

	addFilterout(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Protocol:  unix.ETH_P_IP,
	})

	addFilterin(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Protocol:  unix.ETH_P_IPV6,
	})

	addFilterout(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Protocol:  unix.ETH_P_IPV6,
	})

	for _, filter := range p.filters {
		if err := p.handle.FilterAdd(filter); err != nil {
			if err := p.handle.FilterReplace(filter); err != nil {
				return err
			}
		}
	}

	return nil
}

func newProbe(iface netlink.Link) (*probe, error) {
	log.Println("Creating a new probe")

	if err := setRlimit(); err != nil {
		log.Printf("Failed setting rlimit: %v", err)
		return nil, err
	}

	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)

	if err != nil {
		log.Printf("Failed getting netlink handle: %v", err)
		return nil, err
	}

	prbe := probe{
		iface:  iface,
		handle: handle,
	}

	if err := prbe.loadObjects(); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return nil, err
	}

	if err := prbe.createQdisc(); err != nil {
		log.Printf("Failed creating qdisc: %v", err)
		return nil, err
	}

	if err := prbe.createFilters(); err != nil {
		log.Printf("Failed creating qdisc filters: %v", err)
		return nil, err
	}

	return &prbe, nil
}

// func print global metrics
func (p *probe) PrintGlobalMetrics() {
	globalmetricsmap := p.bpfObjects.probeMaps.Globalmetrics
	keyg := uint32(0)
	var gm probeGlobalMetrics
	err := globalmetricsmap.Lookup(keyg, &gm)
	if err != nil {
		log.Fatalf("Failed to lookup global metrics: %v", err)
	}

	log.Printf("")
	log.Printf("Global metrics:")
	log.Printf("---------------")
	log.Printf("Total packets processed: %v", gm.TotalProcessedpackets)
	log.Printf("Total packets analyzed (TCP+UDP): %v", gm.TotalTcpudppackets)
	log.Printf("Total TCP packets analyzed: %v", gm.TotalTcppackets)
	log.Printf("Total UDP packets analyzed: %v", gm.TotalUdppackets)
	log.Printf("Total flows analyzed: %v", gm.TotalFlows)
	log.Printf("Total TCP flows analyzed: %v", gm.TotalTcpflows)
	log.Printf("Total UDP flows analyzed: %v", gm.TotalUdpflows)
	log.Printf("")
}

func writeFlowStatsToFile(filename string, flowid probeFlowId, flowMetrics probeFlowMetrics) {

	// Open the log file
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()

	// Check if the file is empty
	fi, err := f.Stat()
	if err != nil {
		log.Println(err)
	}

	// If the file is empty, write the header
	if fi.Size() == 0 {
		_, err = f.WriteString("Protocol,Local,Remote,PacketsIn,PacketsOut,BytesIn,BytesOut,TsDuration,TsStart,TsCurrent,FinCounter,FlowClosed\n")
		if err != nil {
			log.Println(err)
		}
	}

	// Write the flow stats to the log file
	_, err = f.WriteString(fmt.Sprintf("%v,%v:%v,%v:%v,%v,%v,%v,%v,%v,%v,%v,%v,%v\n",
		flowid.Protocol, net.IP(flowid.L_ip.In6U.U6Addr8[:]).String(), flowid.L_port, net.IP(flowid.R_ip.In6U.U6Addr8[:]).String(), flowid.R_port, flowMetrics.PacketsIn, flowMetrics.PacketsOut, flowMetrics.BytesIn, flowMetrics.BytesOut, float64(flowMetrics.TsCurrent-flowMetrics.TsStart)/1000000, flowMetrics.TsStart, flowMetrics.TsCurrent, flowMetrics.FinCounter, flowMetrics.FlowClosed))
	if err != nil {
		log.Println(err)
	}

}

// LogFlowTable writes all flows remaining in the FlowTable to the log.
func LogFlowTable(ft *FlowTable) {
	ft.Range(func(key, value interface{}) bool {
		flowId := key.(probeFlowId)
		flowMetrics := value.(probeFlowMetrics)
		writeFlowStatsToFile("flows_closed.txt", flowId, flowMetrics)
		return true
	})
}

func (p *probe) Close(ft *FlowTable) error {

	p.PrintGlobalMetrics()

	log.Println("Removing qdisc")
	if err := p.handle.QdiscDel(p.qdisc); err != nil {
		log.Println("Failed deleting qdisc")
		return err
	}

	log.Println("Deleting handle")
	p.handle.Delete()

	log.Println("Closing eBPF object")
	if err := p.bpfObjects.Close(); err != nil {
		log.Println("Failed closing eBPF object")
		return err
	}

	LogFlowTable(ft)
	return nil
}

func UnmarshalFlowRecord(in []byte) (Flowrecord, bool) {
	//gather bits from []byte to form L_ip of type struct{ In6U struct{ U6Addr8 [16]uint8 } }
	var l_ip struct{ In6U struct{ U6Addr8 [16]uint8 } }
	for i := 0; i < 16; i++ {
		l_ip.In6U.U6Addr8[i] = in[i]
	}
	//gather bits from []byte to form R_ip of type struct{ In6U struct{ U6Addr8 [16]uint8 } }
	var r_ip struct{ In6U struct{ U6Addr8 [16]uint8 } }
	for i := 0; i < 16; i++ {
		r_ip.In6U.U6Addr8[i] = in[i+16]
	}

	// form the probeFlowId struct
	f_id := probeFlowId{
		L_ip:     l_ip,
		R_ip:     r_ip,
		L_port:   binary.LittleEndian.Uint16(in[32:34]),
		R_port:   binary.LittleEndian.Uint16(in[34:36]),
		Protocol: in[36],
	}

	// form the probeFlowMetrics struct
	f_m := probeFlowMetrics{
		PacketsIn:    binary.LittleEndian.Uint32(in[40:44]),
		PacketsOut:   binary.LittleEndian.Uint32(in[44:48]),
		BytesIn:      binary.LittleEndian.Uint64(in[48:56]),
		BytesOut:     binary.LittleEndian.Uint64(in[56:64]),
		TsStart:      binary.LittleEndian.Uint64(in[64:72]),
		TsCurrent:    binary.LittleEndian.Uint64(in[72:80]),
		FinCounter:   in[80],
		AckCounter:   in[81],
		FlowClosed:   in[82],
		SynOrUdpToRb: in[83] == 1,
	}
	//log.Printf("Binary: L_ip %v R_ip %v L_port %v R_port %v Protocol %v", in[0:16], in[16:32], in[32:34], in[34:36], in[36])
	//log.Printf("Binary: PacketsIn %v PacketsOut %v BytesIn %v BytesOut %v TsStart %v TsCurrent %v Fin %v", in[37:41], in[41:45], in[45:53], in[53:61], in[61:69], in[69:77], in[77])

	return Flowrecord{
		fid: f_id,
		fm:  f_m,
	}, true
}

func CheckIfStaleEntry(flowid probeFlowId, flowmetrics probeFlowMetrics) bool {
	var stale bool
	lastts := flowmetrics.TsCurrent
	now := timer.GetNanosecSinceBoot()
	time_flow := now - lastts
	if (flowmetrics.PacketsIn + flowmetrics.PacketsOut) > 1 {
		if (flowid.Protocol == 6) && (time_flow > (TCP_IDLE_TIME - EVICTION_TIME_NS)) { //TCP and 300000ms = 5min //plus 10sec que es la frecuencia del evict
			stale = true
		} else if (flowid.Protocol == 17) && (time_flow > (UDP_IDLE_TIME - EVICTION_TIME_NS)) { //UDP and 200000ms = 3min and 20s //plus 5sec que es la frecuencia del evict
			stale = true
		}
	} else if time_flow > (SINGLETON_TIME - EVICTION_TIME_NS) { //10s //plus 10sec que es la frecuencia del evict -> no packets have been observed for this flow 10 seconds after the initial packet
		stale = true
	}
	return stale
}

// Run starts the probe
func Run(ctx context.Context, iface netlink.Link, ft *FlowTable) error {
	log.Printf("Starting up the probe at interface %v", iface.Attrs().Name)

	probe, err := newProbe(iface)
	if err != nil {
		return err
	}

	flowstrackermap := probe.bpfObjects.probeMaps.Flowstracker

	//evict all entries from the flowstracker map and copy to the flowtable every 5 seconds
	tickerevict := time.NewTicker(time.Second * EVICTION_TIME)
	defer tickerevict.Stop()
	go func() {
		for range tickerevict.C {
			//ToDo in ConnStats Version 2.0: Deal with updating the flowtable considering the flows that were created there because didn't fit in the hashmap and came via ringbuf. Maybe checking the oldest tstart

			iterator := flowstrackermap.Iterate()
			var fid probeFlowId
			var flowmetrics probeFlowMetrics
			keysToDelete := []probeFlowId{}
			//iterate over the hash map flowstrackermap
			for iterator.Next(&fid, &flowmetrics) {
				//lookup if flow id exists in the flowtable ft and update accordingly
				//if true to UpdateFlowTable (FlowTable updated successfully), delete packets and bytes metrics from flowstrackermap
				ft.Store(fid, flowmetrics)

				if CheckIfStaleEntry(fid, flowmetrics) {
					keysToDelete = append(keysToDelete, fid)
				}
			}
			//if keys to delete is not empty, delete them from the flowstrackermap and the flowtable and write the flow stats to a file
			if len(keysToDelete) > 0 {
				writeFlowStatsToFile("flows_closed.txt", fid, flowmetrics)
				flowstrackermap.BatchDelete(keysToDelete, nil)
				for _, key := range keysToDelete {
					ft.Remove(key) //Delete also from the flowtable o hacer un metodo remove batch
				}
				//log.Printf("FlowTable size: %v\n", ft.Size())
				//log.Printf(" ")
			}

			flowstrackermap.BatchDelete(keysToDelete, nil)
			for _, key := range keysToDelete {
				ft.Remove(key) //Delete also from the flowtable o hacer un metodo remove batch
			}
			//log.Printf("FlowTable size: %v\n", ft.Size())
			//log.Printf(" ")
		}
	}()

	// Create a ring buffer reader
	pipe := probe.bpfObjects.probeMaps.Pipe
	ringreader, err := ringbuf.NewReader(pipe)
	if err != nil {
		log.Println("Failed creating ringbuf reader")
		return err
	}

	go func() {
		for {
			event, err := ringreader.Read()
			if err != nil {
				log.Printf("Failed reading ringbuf event: %v", err)
				return
			}
			//log.Printf("Pkt received from ringbuf: %+v", event.RawSample)
			flowrecord, ok := UnmarshalFlowRecord(event.RawSample)
			if !ok {
				log.Printf("Could not unmarshall flow record: %+v", event.RawSample)
				continue
			}
			log.Printf("Flowrecord unmarshalled: %+v", flowrecord)

			// if flow record fin is true, delete from flow table
			if flowrecord.fm.FlowClosed == 1 || flowrecord.fm.FlowClosed == 2 {
				writeFlowStatsToFile("flows_closed.txt", flowrecord.fid, flowrecord.fm)
				ft.Remove(flowrecord.fid)
			}

			// ToDo in ConnStats Version 2.0: Deal with flows that didn't fit in the hashmap
			// } else if flowrecord.fm.SynOrUdpToRb {
			// 	//it's a syn tcp or a udp packet that didn't fit in the hashmap -> add it to the flowtable
			// 	ft.UpdateFlowTableIfSynOrUdpToRb(flowrecord.fid, flowrecord.fm)
			// 	//ft.UpdateFlowTableIfSynOrUdpToRb(flowrecord.fid, flowrecord.fm)
			// } else {
			// 	//it's a tcp no syn packet, add it only if it already exists in the flowtable
			// 	ft.UpdateFlowTableIfExists(flowrecord.fid, flowrecord.fm)
			// }
		}
	}()

	for {

		<-ctx.Done()

		tickerevict.Stop()
		//LogFlowTable(ft)
		return probe.Close(ft)

	}
}
