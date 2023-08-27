package probe

import (
	"context"
	"log"

	"github.com/cilium/ebpf/perf"
	"github.com/gabspt/ConnectionStats/clsact"
	"github.com/gabspt/ConnectionStats/internal/flowtable"
	"github.com/gabspt/ConnectionStats/internal/packet"
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

	// log.Println("Removing qdisc filters")

	// for _, filter := range p.filters {
	// 	if err := p.handle.FilterDel(filter); err != nil {
	// 		log.Println("Failed deleting qdisc filters")
	// 		return err
	// 	}
	// }

	log.Println("Deleting handle")
	p.handle.Delete()

	log.Println("Closing eBPF object")
	if err := p.bpfObjects.Close(); err != nil {
		log.Println("Failed closing eBPF object")
		return err
	}

	return nil
}

func Run(ctx context.Context, iface netlink.Link, ft *flowtable.FlowTable) error {
	log.Println("Starting up the probe")

	probe, err := newProbe(iface)

	if err != nil {
		return err
	}

	pipe := probe.bpfObjects.probeMaps.Pipe

	reader, err := perf.NewReader(pipe, 10)

	if err != nil {
		log.Println("Failed creating perf reader")
		return err
	}

	c := make(chan []byte)

	go func() {
		for {
			event, err := reader.Read()
			if err != nil {
				log.Printf("Failed reading perf event: %v", err)
				return
			}
			c <- event.RawSample //the event(network packet) is in c
		}
	}()

	//flowtable := flowtable.NewFlowTable()
	//connection := flowtable.NewConnection()

	go func() {
		for range ft.Ticker.C {
			ft.Prune()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			// reader.Close()
			ft.Ticker.Stop()
			return probe.Close()

		case pkt := <-c:
			packetAttrs, ok := packet.UnmarshalBinary(pkt)
			if !ok {
				log.Printf("Could not unmarshall packet: %+v", pkt)
				continue
			}
			packet.CalcStats(packetAttrs, ft)
			//flowtable.Range()
		}
	}
}
