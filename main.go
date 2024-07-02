package main

import (
	"compress/gzip"
	"encoding/json"
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

const settings = "settings.json"

var (
	promisc bool = false
	err     error
)

type service struct {
	Port     string        `json:"port"`
	Rotation time.Duration `json:"rotation"`
	Iface    string        `json:"iface"`
	Fname    string        `json:"fname"`
	Snapslen int32         `json:"snapslen"`
	Filter   string        `json:"filter"`
	Zip      bool          `json:"zip"`
	Ng       bool          `json:"ng"`
	Debug    bool          `json:"debug"`
}

type services struct {
	Services []service `json:"services"`
}

func parse(ser *service) {
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
	flag.BoolVar(&ser.Zip, "z", false, "set for compressed output")
	flag.BoolVar(&ser.Ng, "ng", false, "set for pcapng output")
	flag.BoolVar(&ser.Debug, "debug", false, "Enanales debug mode")
	flag.Parse()

	ser.Filter = strings.Join(flag.Args(), " ")

	ser.Port = strconv.Itoa(int(p))
	ser.Rotation = time.Duration(G) * time.Second
	ser.Iface = i
	ser.Fname = w
	if ser.Ng {
		ser.Fname += "ng"
	}
	if ser.Zip {
		ser.Fname += ".gz"
	}
	if s <= 0 {
		s = 262144
	}
	ser.Snapslen = int32(s)

	if ser.Filter == "" {
		ser.Filter = "tcp and port " + ser.Port
	}

	if ser.Debug {
		fmt.Printf("Port: %v\n", ser.Port)
		fmt.Printf("Rotation: %v\n", ser.Rotation)
		fmt.Printf("Interface: %v\n", ser.Iface)
		fmt.Printf("Filename: %v\n", ser.Fname)
		fmt.Printf("Snapshot length: %v\n", ser.Snapslen)
		fmt.Printf("Filter: %v\n", ser.Filter)
		fmt.Printf("Zip: %v\n", ser.Zip)
		fmt.Printf("Pcapng: %v\n", ser.Ng)
	}
}

func handle_packets(src *gopacket.PacketSource, handle *pcap.Handle, s *service) {
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
			n := strings.ReplaceAll(s.Fname, "%Y", strconv.Itoa(ct.Year()))
			n = strings.ReplaceAll(n, "%m", strconv.Itoa(int(ct.Month())))
			n = strings.ReplaceAll(n, "%d", strconv.Itoa(ct.Day()))
			n = strings.ReplaceAll(n, "%H", strconv.Itoa(ct.Hour()))
			n = strings.ReplaceAll(n, "%M", strconv.Itoa(ct.Minute()))
			n = strings.ReplaceAll(n, "%S", strconv.Itoa(ct.Second()))

			out, err = os.OpenFile(n, os.O_RDWR|os.O_CREATE, 0666)
			if err != nil {
				log.Fatalf("Error opening %v out file: %v\n", n, err)
			}

			if s.Zip {
				gzWriter = gzip.NewWriter(out)
			}

			if s.Ng {
				if s.Zip {
					ngWriter, err = pcapgo.NewNgWriter(gzWriter, handle.LinkType())
				} else {
					ngWriter, err = pcapgo.NewNgWriter(out, handle.LinkType())
				}
				if err != nil {
					log.Fatalf("error creating file: %v\n", err)
				}
			} else {
				if s.Zip {
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
		if s.Ng {
			err = ngWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		} else {
			err = writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
		if err != nil {
			log.Fatalf("error writing packet to file: %v", err)
		}

		// DUMP END
		if total == recived {
			if s.Debug {
				fmt.Printf("Captured %v packets in %v\n", count, out.Name())
				fmt.Printf("%v %v\n", s.Zip, s.Ng)
			}
			count = 0
			if s.Ng {
				ngWriter.Flush()
			}
			if s.Zip {
				gzWriter.Close()
			}
			out.Close()
		}
	}
}

func capture(s *service) {
	handle, err := pcap.OpenLive(s.Iface, s.Snapslen, promisc, s.Rotation)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(s.Filter)
	if err != nil {
		log.Fatal(err)
	}

	if s.Debug {
		fmt.Printf("Capturing on %v...\n", s.Port)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	handle_packets(packetSource, handle, s)
}

// sudo ./godump -debug -G 60 -w "test_%Y-%m-%d_%H.%M.%S.pcap" -s 0 -i eth0 tcp and port 4444
func main() {
	if _, err := os.Stat(settings); os.IsNotExist(err) {
		var s service
		parse(&s)
		capture(&s)
		return
	}

	file, err := os.Open(settings)
	if err != nil {
		log.Fatalf("Error opening file: %v\n", err)
	}

	var data services
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		log.Fatalf("Error decoding JSON: %v\n", err)
	}
	file.Close()

	for i := range data.Services {
		data.Services[i].Rotation *= time.Second
		if data.Services[i].Ng {
			data.Services[i].Fname += "ng"
		}
		if data.Services[i].Zip {
			data.Services[i].Fname += ".gz"
		}
		if data.Services[i].Snapslen <= 0 {
			data.Services[i].Snapslen = 262144
		}
		if data.Services[i].Filter == "" {
			data.Services[i].Filter = "tcp and port " + data.Services[i].Port
		} else {
			words := strings.Split(data.Services[i].Filter, " ")
			data.Services[i].Port = words[len(words)-1]
		}
	}

	for i, ser := range data.Services {
		if ser.Debug {
			fmt.Printf("Service: %v\n", i)
			fmt.Printf("Port: %v\n", ser.Port)
			fmt.Printf("Rotation: %v\n", ser.Rotation)
			fmt.Printf("Interface: %v\n", ser.Iface)
			fmt.Printf("Filename: %v\n", ser.Fname)
			fmt.Printf("Snapshot length: %v\n", ser.Snapslen)
			fmt.Printf("Filter: %v\n", ser.Filter)
			fmt.Printf("Zip: %v\n", ser.Zip)
			fmt.Printf("Pcapng: %v\n", ser.Ng)
			fmt.Printf("Debug: %v\n\n", ser.Debug)
		}
		go capture(&data.Services[i])
	}

	select {}
}
