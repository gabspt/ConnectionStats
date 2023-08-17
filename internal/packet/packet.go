package packet

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log"
	"net/netip"

	//"github.com/pouriyajamshidi/flat/internal/flowtable"
	"github.com/gabspt/ConnectionStats/internal/flowtable"
)

/*

Remember that net.IP is just a []byte

The To4() converts it to the 4-byte representation

Example for net.Parse(192.168.1.1):

Original:  net.IP{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xc0, 0xa8, 0x1, 0x1}
After To4: net.IP{0xc0, 0xa8, 0x1, 0x1}

*/

const (
	udp = "UDP"
	tcp = "TCP"
)

type Packet struct {
	SrcIP     netip.Addr
	DstIP     netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	Ttl       uint8
	Syn       bool
	Ack       bool
	Fin       bool
	TimeStamp uint64
	Outbound  bool
	Len       uint32
}

func hash(value []byte) uint64 {
	hash := fnv.New64a()
	hash.Write(value)
	return hash.Sum64()
}

func (pkt *Packet) Hash() uint64 {
	tmp := make([]byte, 2)

	var src []byte
	var dst []byte
	var proto []byte

	binary.BigEndian.PutUint16(tmp, pkt.SrcPort)
	src = append(pkt.SrcIP.AsSlice(), tmp...)

	binary.BigEndian.PutUint16(tmp, pkt.DstPort)
	dst = append(pkt.DstIP.AsSlice(), tmp...)

	binary.BigEndian.PutUint16(tmp, uint16(pkt.Protocol))
	proto = append(proto, tmp...)

	return hash(src) + hash(dst) + hash(proto)
}

func UnmarshalBinary(in []byte) (Packet, bool) {
	srcIP, ok := netip.AddrFromSlice(in[0:16])

	if !ok {
		return Packet{}, ok
	}

	dstIP, ok := netip.AddrFromSlice(in[16:32])

	if !ok {
		return Packet{}, ok
	}

	return Packet{
		SrcIP:     srcIP,
		SrcPort:   binary.BigEndian.Uint16(in[32:34]),
		DstIP:     dstIP,
		DstPort:   binary.BigEndian.Uint16(in[34:36]),
		Protocol:  in[36],
		Ttl:       in[37],
		Syn:       in[38] == 1, //If in[38] == 1 then Syn=true, if in[38] == 0 then Syn=false
		Ack:       in[39] == 1, //If in[39] == 1 then Ack=true, if in[38] == 0 then Ack=false
		Fin:       in[40] == 1, //If in[40] == 1 then Fin=true, if in[38] == 0 then Fin=false
		TimeStamp: binary.LittleEndian.Uint64(in[41:49]),
		Outbound:  in[49] == 1, //If in[49] == 1 then Outbound=true, if in[38] == 0 then Outbound=false
		Len:       binary.BigEndian.Uint32(in[50:54]),
	}, true
}

var ipProtoNums = map[uint8]string{
	6:  "TCP",
	17: "UDP",
}

func CalcStats(pkt Packet, table *flowtable.FlowTable) {
	proto, ok := ipProtoNums[pkt.Protocol]

	if !ok {
		log.Print("Failed fetching protocol number")
		return
	}

	//Calculate packet hash
	pktHash := pkt.Hash()

	//c := flowtable.NewConnection()

	//Search if this Hash already exists in the table, if nothing was found return 0,false, else: ts,true
	c, ok := table.Get(pktHash)

	if !ok && ((pkt.Syn) || (proto == udp)) { //new connection and it is a syn tcp or a new udp conn
		//ask if the pkt is inbound or outbound and update the corresponding counters
		if pkt.Outbound {
			c.Packets_out++
			c.Bytes_out = c.Bytes_out + uint64(pkt.Len)
			c.Ts_ini = pkt.TimeStamp
		} else {
			c.Packets_in++
			c.Bytes_in = c.Bytes_in + uint64(pkt.Len)
			c.Ts_ini = pkt.TimeStamp
		}
		//add new connection to the table
		table.Insert(pktHash, c)
		return

	} else { //existing connection, in other words it's a new packet that belongs to an existing connection
		//ask if the pkt is inbound or outbound and update the corresponding counters
		if pkt.Outbound {
			c.Packets_out++
			c.Bytes_out = c.Bytes_out + uint64(pkt.Len)
			c.Ts_fin = pkt.TimeStamp
		} else {
			c.Packets_in++
			c.Bytes_in = c.Bytes_in + uint64(pkt.Len)
			c.Ts_fin = pkt.TimeStamp
		}
		//in this case "Insert" updates the existing connection with new value c
		table.Insert(pktHash, c)

		//preguntar si es fin

		//si es fin empezar contadores nuevos locales temporales, cuando vea que han pasado 2fin y 2ack para esta conexion, autoaticamente eliminarla de la tabla
	}

	convertIPToString := func(address netip.Addr) string {
		return address.Unmap().String()
	}

	//print connection statistics
	fmt.Printf("(%v) Flow | A: %v:%v B: %v:%v | inpps: %v | outpps: %v | inBpp: %v | outBpp: %v| inBoutB: %v | inPoutP: %v\n", // nice format
		// fmt.Printf("(%v) Flow | A: %v:%v | B: %v:%v | In_pps: %v |\tlatency: %.3f ms\n",
		proto,
		convertIPToString(pkt.DstIP),
		pkt.DstPort,
		convertIPToString(pkt.SrcIP),
		pkt.SrcPort,
		uint64(c.Packets_in)/(uint64(c.Ts_fin)-uint64(c.Ts_ini)),
		uint64(c.Packets_out)/(uint64(c.Ts_fin)-uint64(c.Ts_ini)),
		c.Bytes_in/c.Packets_in,
		c.Bytes_out/c.Packets_out,
		c.Bytes_in/c.Bytes_out,
		c.Packets_in/c.Packets_out,
	)

	table.Remove(pktHash)

}
