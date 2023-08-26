package packet

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log"
	"net/netip"

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
		Syn:       in[37] == 1, //If in[38] == 1 then Syn=true, if in[38] == 0 then Syn=false
		Ack:       in[38] == 1, //If in[39] == 1 then Ack=true, if in[38] == 0 then Ack=false
		Fin:       in[39] == 1, //If in[40] == 1 then Fin=true, if in[38] == 0 then Fin=false
		TimeStamp: binary.LittleEndian.Uint64(in[40:48]),
		Outbound:  in[48] == 1, //If in[49] == 1 then Outbound=true, if in[38] == 0 then Outbound=false
		Len:       binary.BigEndian.Uint32(in[49:53]),
	}, true
}

var ipProtoNums = map[uint8]string{
	6:  "TCP",
	17: "UDP",
}

var contFin int = 0
var wait4ACK bool = false

func CalcStats(pkt Packet, table *flowtable.FlowTable) {

	convertIPToString := func(address netip.Addr) string {
		return address.Unmap().String()
	}

	proto, ok := ipProtoNums[pkt.Protocol]

	if !ok {
		log.Print("Failed fetching protocol number")
		return
	}

	//Calculate packet hash
	pktHash := pkt.Hash()

	//c := flowtable.NewConnection()

	//Search if this Hash already exists in the table, if nothing was found return 0,false, else: ts,true
	conn, ok := table.Get(pktHash)

	if !ok { //&& ((pkt.Syn) || (proto == udp)) { //new connection and it is a syn tcp or a new udp conn
		//ask if the pkt is inbound or outbound and update the corresponding counters
		if pkt.Syn || (proto == udp) {
			if pkt.Outbound {
				conn.Packets_out++
				conn.Bytes_out = conn.Bytes_out + uint64(pkt.Len)
				conn.Ts_ini = pkt.TimeStamp
			} else {
				conn.Packets_in++
				conn.Bytes_in = conn.Bytes_in + uint64(pkt.Len)
				conn.Ts_ini = pkt.TimeStamp
			}
			conn.AIp = pkt.SrcIP
			conn.APort = pkt.SrcPort
			conn.BIp = pkt.DstIP
			conn.BPort = pkt.DstPort

			//add new connection to the table
			table.Insert(pktHash, conn)

			fmt.Printf("GOT A NEW CONNECTION\n")
			fmt.Printf("(%v) (%v) Flow | A: %v:%v B: %v:%v\n", // nice format
				proto,
				pktHash,
				convertIPToString(pkt.SrcIP),
				pkt.SrcPort,
				convertIPToString(pkt.DstIP),
				pkt.DstPort,
			)
			return
		}
		return
	} else { //existing connection, in other words it's a new packet that belongs to an existing connection
		//ask if the pkt is inbound or outbound and update the corresponding counters
		if pkt.Outbound {
			conn.Packets_out++
			conn.Bytes_out = conn.Bytes_out + uint64(pkt.Len)
			conn.Ts_fin = pkt.TimeStamp
		} else {
			conn.Packets_in++
			conn.Bytes_in = conn.Bytes_in + uint64(pkt.Len)
			conn.Ts_fin = pkt.TimeStamp
		}
		//in this case "Insert" updates the existing connection with new value c
		table.Insert(pktHash, conn)

		//Detect FIN packet
		//if pkt.Fin {
		//si es fin empezar contadores nuevos locales temporales, cuando vea que han pasado 2fin y 2ack para esta conexion, autoaticamente eliminarla de la tabla
		//de momento no soy tan exquisita y al primer FIN que vea elimino la conexion
		//	table.Remove(pktHash)
		//}
		//print connection statistics
		inpps := float64(conn.Packets_in) / ((float64(conn.Ts_fin) - float64(conn.Ts_ini)) / 1000000000)
		outpps := float64(conn.Packets_out) / ((float64(conn.Ts_fin) - float64(conn.Ts_ini)) / 1000000000)
		inBpp := float64(0)
		if conn.Packets_in != 0 {
			inBpp = float64(conn.Bytes_in) / float64(conn.Packets_in)
		}
		outBpp := float64(0)
		if conn.Packets_out != 0 {
			outBpp = float64(conn.Bytes_out) / float64(conn.Packets_out)
		}
		inBoutB := float64(0)
		if conn.Bytes_out != 0 {
			inBoutB = float64(conn.Bytes_in) / float64(conn.Bytes_out)
		}
		inPoutP := float64(0)
		if conn.Packets_out != 0 {
			inPoutP = float64(conn.Packets_in) / float64(conn.Packets_out)
		}

		fmt.Printf("(%v) (%v) Flow | A: %v:%v B: %v:%v | inpps: %.2f | outpps: %.2f | inBpp: %.2f | outBpp: %.2f| inBoutB: %.2f | inPoutP: %.2f\n", // nice format
			// fmt.Printf("(%v) Flow | A: %v:%v | B: %v:%v | In_pps: %v |\tlatency: %.3f ms\n",
			proto,
			pktHash,
			convertIPToString(conn.AIp),
			conn.APort,
			convertIPToString(conn.BIp),
			conn.BPort,
			inpps,
			outpps,
			inBpp,
			outBpp,
			inBoutB,
			inPoutP,
		)

		fmt.Printf("conn: %+v\n", conn)
		fmt.Printf("pkt: %+v\n", pkt)
		fmt.Printf(" \n")

		if pkt.Fin {
			//si es fin empezar contadores nuevos locales temporales, cuando vea que han pasado 2fin y 2ack para esta conexion, autoaticamente eliminarla de la tabla
			contFin++
			if contFin >= 2 {
				wait4ACK = true
				contFin = 0
			}
		} else if wait4ACK && pkt.Ack && !pkt.Syn {
			if wait4ACK && pkt.Ack && !pkt.Syn && !pkt.Fin {
				//that was the last packet of the TCP connection. The TCP connection is closed. Remove it.
				table.Remove(pktHash)
				wait4ACK = false
				table.CountActiveConns()
			}
		}

	}

}
