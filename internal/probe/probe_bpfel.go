// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || loong64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64

package probe

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type probeFlowId struct {
	L_ip     struct{ In6U struct{ U6Addr8 [16]uint8 } }
	R_ip     struct{ In6U struct{ U6Addr8 [16]uint8 } }
	L_port   uint16
	R_port   uint16
	Protocol uint8
	_        [3]byte
}

type probeFlowMetrics struct {
	PacketsIn  uint32
	PacketsOut uint32
	BytesIn    uint64
	BytesOut   uint64
	TsStart    uint64
	TsCurrent  uint64
}

// loadProbe returns the embedded CollectionSpec for probe.
func loadProbe() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ProbeBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load probe: %w", err)
	}

	return spec, err
}

// loadProbeObjects loads probe and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*probeObjects
//	*probePrograms
//	*probeMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadProbeObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadProbe()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// probeSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type probeSpecs struct {
	probeProgramSpecs
	probeMapSpecs
}

// probeSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type probeProgramSpecs struct {
	Connstatsin  *ebpf.ProgramSpec `ebpf:"connstatsin"`
	Connstatsout *ebpf.ProgramSpec `ebpf:"connstatsout"`
}

// probeMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type probeMapSpecs struct {
	Flowstracker *ebpf.MapSpec `ebpf:"flowstracker"`
	Pipe         *ebpf.MapSpec `ebpf:"pipe"`
}

// probeObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadProbeObjects or ebpf.CollectionSpec.LoadAndAssign.
type probeObjects struct {
	probePrograms
	probeMaps
}

func (o *probeObjects) Close() error {
	return _ProbeClose(
		&o.probePrograms,
		&o.probeMaps,
	)
}

// probeMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadProbeObjects or ebpf.CollectionSpec.LoadAndAssign.
type probeMaps struct {
	Flowstracker *ebpf.Map `ebpf:"flowstracker"`
	Pipe         *ebpf.Map `ebpf:"pipe"`
}

func (m *probeMaps) Close() error {
	return _ProbeClose(
		m.Flowstracker,
		m.Pipe,
	)
}

// probePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadProbeObjects or ebpf.CollectionSpec.LoadAndAssign.
type probePrograms struct {
	Connstatsin  *ebpf.Program `ebpf:"connstatsin"`
	Connstatsout *ebpf.Program `ebpf:"connstatsout"`
}

func (p *probePrograms) Close() error {
	return _ProbeClose(
		p.Connstatsin,
		p.Connstatsout,
	)
}

func _ProbeClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed probe_bpfel.o
var _ProbeBytes []byte
