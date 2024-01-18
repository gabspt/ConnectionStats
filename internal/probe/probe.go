package probe

import (
	"context"
	"encoding/binary"
	"log"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/gabspt/ConnectionStats/clsact"
	"github.com/gabspt/ConnectionStats/internal/timer"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/connstats.c - -O3  -Wall -Werror -Wno-address-of-packed-member

//

const tenMegaBytes = 1024 * 1024 * 10 // 10MB

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
	log.Println("Setting rlimit")

	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: tenMegaBytes,
		Max: tenMegaBytes,
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

func (p *probe) Close() error {
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
		L_port:   binary.BigEndian.Uint16(in[32:34]),
		R_port:   binary.BigEndian.Uint16(in[34:36]),
		Protocol: in[36],
	}

	// form the probeFlowMetrics struct
	f_m := probeFlowMetrics{
		PacketsIn:  binary.BigEndian.Uint32(in[37:41]),
		PacketsOut: binary.BigEndian.Uint32(in[41:45]),
		BytesIn:    binary.BigEndian.Uint64(in[45:53]),
		BytesOut:   binary.BigEndian.Uint64(in[53:61]),
		TsStart:    binary.BigEndian.Uint64(in[61:69]),
		TsCurrent:  binary.BigEndian.Uint64(in[69:77]),
		Fin:        in[77] == 1,
	}

	return Flowrecord{
		fid: f_id,
		fm:  f_m,
	}, true
}

// Prune deletes stale entries (havnt been updated in more than 60 seconds) directly from the hash map Flowstracker
func (p *probe) Prune() {
	now := timer.GetNanosecSinceBoot()

	flowstrackermap := p.bpfObjects.probeMaps.Flowstracker
	iterator := flowstrackermap.Iterate()
	var fid probeFlowId
	var flowmetrics probeFlowMetrics
	for iterator.Next(&fid, &flowmetrics) {
		lastts := flowmetrics.TsCurrent
		if (now-lastts)/1000000 > 60000 {
			log.Printf("Pruning stale entry from flowstracker map: %v after %vms", fid, (now-lastts)/1000000)
			flowstrackermap.Delete(&fid)
		}
	}
}

// Run starts the probe
func Run(ctx context.Context, iface netlink.Link, ft *FlowTable) error {
	log.Println("Starting up the probe")

	probe, err := newProbe(iface)
	if err != nil {
		return err
	}

	flowstrackermap := probe.bpfObjects.probeMaps.Flowstracker

	//evict all entries from the flowstracker map and copy to the flowtable every 5 seconds
	tickerevict := time.NewTicker(time.Second * 5)
	defer tickerevict.Stop()
	//revisar esta go routine, a ver si la tengo que hacer con el mismo estilo de select que la de Prune
	go func() {
		for range tickerevict.C {
			//evict all entries from the flowstracker map and copy to the flowtable
			//cuando yo haga el evict cada 5s no puedo simplemente dumpear el hash map ahi sin ver lo que habia
			//porque el flowtable tiene flows que vinieron por el ringbuf y no entraron al hasmap,
			//entonces tengo que chequear si el flow ya esta en el flowtable y si es asi actualizarlo, cogiendo el tstart mas antiguo y tcurrent mas reciente y sumando los paquetes y bytes
			//flowstrackermap := probe.bpfObjects.probeMaps.Flowstracker
			iterator := flowstrackermap.Iterate()
			var fid probeFlowId
			var flowmetrics probeFlowMetrics
			//iterate over the hash map and copy all entries to the flowtable
			for iterator.Next(&fid, &flowmetrics) {
				// do lookup if flow id exists in the flowtable ft
				value, found := ft.Load(fid)
				if !found {
					ft.Store(fid, flowmetrics)
				} else {
					existingflowm, ok := value.(probeFlowMetrics)
					if ok {
						flowmetrics.PacketsIn += existingflowm.PacketsIn
						flowmetrics.PacketsOut += existingflowm.PacketsOut
						flowmetrics.BytesIn += existingflowm.BytesIn
						flowmetrics.BytesOut += existingflowm.BytesOut
						if existingflowm.TsStart < flowmetrics.TsStart {
							flowmetrics.TsStart = existingflowm.TsStart
						}
						if existingflowm.TsCurrent > flowmetrics.TsCurrent {
							flowmetrics.TsCurrent = existingflowm.TsCurrent
						}
						ft.Store(fid, flowmetrics)
					} else {
						log.Printf("Could not convert value to probeFlowMetrics: %+v, store anyway", value)
						ft.Store(fid, flowmetrics)
					}
				}
			}
		}
	}()

	pipe := probe.bpfObjects.probeMaps.Pipe
	ringreader, err := ringbuf.NewReader(pipe)
	if err != nil {
		log.Println("Failed creating ringbuf reader")
		return err
	}

	//revisar esta go routine, a ver si la tengo que hacer con el mismo estilo de select que la de Prune
	go func() {
		for {
			event, err := ringreader.Read()
			if err != nil {
				log.Printf("Failed reading ringbuf event: %v", err)
				return
			}
			flowrecord, ok := UnmarshalFlowRecord(event.RawSample)
			if !ok {
				log.Printf("Could not unmarshall flow record: %+v", event.RawSample)
			}

			// Copiar directamente, con esto si existe en el flowtable lo actualiza y si no existe lo agrega
			ft.Store(flowrecord.fid, flowrecord.fm)
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				probe.Prune()
			}
		}
	}()

	for {

		<-ctx.Done()

		ft.Ticker.Stop()
		tickerevict.Stop()
		return probe.Close()

	}
}
