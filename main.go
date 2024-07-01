package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	port     string
	rotation time.Duration
	iface    string
	fname    string
	snapslen int32
	filter   string
	zip      bool
	ng       bool
	debug    bool

	promisc bool = false
	handle  *pcap.Handle
	err     error
)

func parse() {
	var (
		p uint
		G int64
		i string
		w string
		s uint
	)

	flag.UintVar(&p, "p", 4444, "Port to capture")
	flag.Int64Var(&G, "G", 60, "Rotation time in seconds")
	flag.StringVar(&i, "i", "eth0", "Interface to capture")
	flag.StringVar(&w, "w", "pkts_%Y-%m-%d_%H.%M.%S.pcap", "Output filename, example: test_%Y-%m-%d_%H.%M.%S.pcap")
	flag.UintVar(&s, "s", 262144, "Snapshot length")
	flag.BoolVar(&zip, "z", false, "set for compressed output")
	flag.BoolVar(&ng, "ng", false, "set for pcapng output")
	flag.BoolVar(&debug, "debug", false, "Enanales debug mode")
	flag.Parse()

	filter = strings.Join(flag.Args(), " ")

	port = strconv.Itoa(int(p))
	rotation = time.Duration(G) * time.Second
	iface = i
	fname = w
	if ng {
		fname += "ng"
	}
	if zip {
		fname += ".gz"
	}
	if s <= 0 {
		s = 262144
	}
	snapslen = int32(s)

	if filter == "" {
		filter = "tcp and port " + port
	}

	if debug {
		fmt.Printf("Port: %v\n", port)
		fmt.Printf("Rotation: %v\n", rotation)
		fmt.Printf("Interface: %v\n", iface)
		fmt.Printf("Filename: %v\n", fname)
		fmt.Printf("Snapshot length: %v\n", snapslen)
		fmt.Printf("Filter: %v\n", filter)
		fmt.Printf("Zip: %v\n", zip)
		fmt.Printf("Pcapng: %v\n", ng)
	}
}

func handle_packets(src *gopacket.PacketSource, handle *pcap.Handle) {
	var count int = 0
	var total int = 0
	var recived int = 0
	var out *os.File
	var gzWriter *gzip.Writer
	var ngWriter *pcapgo.NgWriter
	var writer *pcapgo.Writer

	for packet := range src.Packets() {

		// DUMP START
		if total == recived {
			ct := time.Now()
			n := strings.ReplaceAll(fname, "%Y", strconv.Itoa(ct.Year()))
			n = strings.ReplaceAll(n, "%m", strconv.Itoa(int(ct.Month())))
			n = strings.ReplaceAll(n, "%d", strconv.Itoa(ct.Day()))
			n = strings.ReplaceAll(n, "%H", strconv.Itoa(ct.Hour()))
			n = strings.ReplaceAll(n, "%M", strconv.Itoa(ct.Minute()))
			n = strings.ReplaceAll(n, "%S", strconv.Itoa(ct.Second()))

			out, err = os.OpenFile(n, os.O_RDWR|os.O_CREATE, 0666)
			if err != nil {
				log.Fatalf("Error opening %v out file: %v\n", n, err)
			}

			if zip {
				gzWriter = gzip.NewWriter(out)
			}

			if ng {
				if zip {
					ngWriter, err = pcapgo.NewNgWriter(gzWriter, handle.LinkType())
				} else {
					ngWriter, err = pcapgo.NewNgWriter(out, handle.LinkType())
				}
				if err != nil {
					log.Fatalf("error creating file: %v\n", err)
				}
			} else {
				if zip {
					writer = pcapgo.NewWriter(gzWriter)
				} else {
					writer = pcapgo.NewWriter(out)
				}
				if err := writer.WriteFileHeader(uint32(handle.SnapLen()), handle.LinkType()); err != nil {
					log.Fatalf("error writing file header: %v\n", err)
				}
			}

			stats, err := handle.Stats()
			if err != nil {
				log.Fatalf("Error while fetching stats: %v\n", err)
			}
			recived = stats.PacketsReceived
		}

		// DUMP PACKET
		count++
		total++
		packet.Metadata().CaptureInfo.InterfaceIndex = 0
		if ng {
			err = ngWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		} else {
			err = writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
		if err != nil {
			log.Fatalf("error writing packet to file: %v", err)
		}

		// DUMP END
		if total == recived {
			if debug {
				fmt.Printf("Captured %v packets in %v\n", count, out.Name())
			}
			count = 0
			if zip {
				gzWriter.Close()
			}
			if ng {
				ngWriter.Flush()
			}
			out.Close()
		}
	}
}

// sudo ./godump -debug -G 60 -w "test_%Y-%m-%d_%H.%M.%S.pcap" -s 0 -i eth0 tcp and port 4444
func main() {
	parse()

	handle, err = pcap.OpenLive(iface, snapslen, promisc, rotation)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	if debug {
		fmt.Println("Capturing...")
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	handle_packets(packetSource, handle)
}
