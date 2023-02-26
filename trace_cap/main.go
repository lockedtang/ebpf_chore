package main

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/containerd/containerd/pkg/cap"
)

//go:embed bpf/bpfelf
var bpfElfData []byte

type data_t struct {
	Tgid uint32
	Pid  uint32
	Uid  uint32
	Cap  int32
	Comm [16]byte
}

const (
	fn     = "kprobe__cap_capable"
	events = "events"
)

func main() {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
	// Load eBPF from an elf file
	reader := bytes.NewReader(bpfElfData)
	collspec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load collection from file: %v\n", err)
		return
	}

	coll, err := ebpf.NewCollectionWithOptions(collspec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSize: ebpf.DefaultVerifierLogSize * 1000}})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create BPF collection: %v", err)
		return
	}
	// Load the eBPF program
	bpfProg := coll.Programs[fn]
	defer bpfProg.Close()
	if bpfProg.VerifierLog != "" {
		fmt.Printf("the BPF Verifier output: %s\n", bpfProg.VerifierLog)
	}

	rd, err := perf.NewReader(coll.Maps[events], os.Getpagesize())
	if err != nil {
		log.Fatalf("creating event reader: %s\n", err)
	}
	// defer rd.Close()

	kp, err := link.Kprobe("cap_capable", bpfProg, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	log.Println("Waiting for events..")
	go handlePerf(rd, stopper)
	<-stopper
	rd.Close()
}

func handlePerf(rd *perf.Reader, stopper chan os.Signal) {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s\n", err)
			continue
		}
		if record.LostSamples != 0 {
			fmt.Printf("Lost samples:  %s", record.RawSample)
			continue
		}
		if err := parseRecord(record, stopper); err != nil {
			if err == io.EOF {
				return
			}
			fmt.Printf("parse record [%v] failed %s\n", record, err)
			continue
		}

	}
}

func parseRecord(record perf.Record, stopper chan os.Signal) error {
	var (
		data data_t
	)
	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &data)
	if err != nil {
		return err
	}
	Capability := cap.FromNumber(int(data.Cap))

	fmt.Printf("uid: [%v] pid:[%v %v] comm :[%s]\tCAP:[%s]\n", data.Uid, data.Tgid, data.Pid, data.Comm, Capability)

	return nil
}
