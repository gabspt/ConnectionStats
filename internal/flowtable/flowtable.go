package flowtable

import (
	"log"
	"sync"
	"time"

	//"github.com/pouriyajamshidi/flat/internal/timer"
	"github.com/gabspt/ConnectionStats/internal/timer"
)

type FlowTable struct {
	Ticker *time.Ticker
	sync.Map
}

type Connection struct {
	Packets_in  uint64
	Packets_out uint64
	Ts_ini      uint64
	Ts_fin      uint64
	Bytes_in    uint64
	Bytes_out   uint64
}

// NewFlowTable Constructs a new FlowTable
func NewFlowTable() *FlowTable {
	return &FlowTable{Ticker: time.NewTicker(time.Second * 10)}
}

// NewConnection Constructs a new Connection
func NewConnection() Connection {
	return Connection{}
}

// add adds packet hash as a new connection and its connection attributes to the FlowTable
func (table *FlowTable) Insert(hash uint64, conn Connection) {
	table.Store(hash, conn)
}

// load loads packet or connection hash and its attributes from the FlowTable
func (table *FlowTable) Get(hash uint64) (Connection, bool) {
	value, ok := table.Load(hash)

	if !ok { //if nothing was found return 0,false
		return Connection{}, ok
	}
	return value.(Connection), true
}

// delete deletes packet hash and its timestamp from the FlowTable
func (table *FlowTable) Remove(hash uint64) {
	_, found := table.Load(hash)

	if found {
		// log.Printf("Removing hash %v from flow table", hash)
		table.Delete(hash)
	} else {
		log.Printf("hash %v is not in flow table", hash)
	}
}

// Prune clears the stale entries (older than 10 seconds) from the FlowTable
func (table *FlowTable) Prune() {
	now := timer.GetNanosecSinceBoot()

	table.Range(func(hash, value interface{}) bool {
		connection, ok := value.(Connection)
		if !ok {
			// Not a Connection instance
			return false
		}

		if (now-connection.Ts_fin)/1000000 > 10000 {
			log.Printf("Pruning stale entry from flow table: %v", hash)

			table.Delete(hash)

			return true
		}
		return false
	})
}

// UpdateTimestamp updates the timestamp value for a packet hash in the FlowTable
/*func (table *FlowTable) UpdateConnection(hash uint64, newConnection Connection) {
	value, ok := table.Load(hash)
	if ok {
		//connection, isConnection := value.(Connection)
		_, isConnection := value.(Connection)
		if isConnection {

			//connection.packets_in++
			//connection.packets_out++
			//connection.bytes_in++
			//connection.bytes_out++
			//connection.ts_fin = newConnection.ts_fin

			//connection = newConnection

			table.Store(hash, newConnection)
		} else {
			log.Printf("Value for hash %v is not a Connection", hash)
		}
	} else {
		log.Printf("Hash %v not found in flow table", hash)
	}
}*/
