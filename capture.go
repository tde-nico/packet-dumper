package main

import (
	"compress/gzip"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func handle_packets(src *gopacket.PacketSource, handle *pcap.Handle, s *service) {
	var (
		count    int = 0
		total    int = 0
		recived  int = 0
		name     string
		out      Writer
		gzWriter *gzip.Writer
		ngWriter *pcapgo.NgWriter
		writer   *pcapgo.Writer
	)

	for packet := range src.Packets() {

		// DUMP START
		if total == recived {
			stats, err := handle.Stats()
			check(err, "Error while fetching stats: %v\n")
			recived = stats.PacketsReceived
			if s.Iface == "lo" {
				recived /= 2
			}
			if stats.PacketsDropped > 0 || stats.PacketsIfDropped > 0 {
				fmt.Printf("Packets dropped: %v\n", stats.PacketsDropped+stats.PacketsIfDropped)
			}
			name = format_time(s.Fname)
			out, gzWriter, ngWriter, writer = init_writers(s, handle, name)
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
		check(err, "Error writing packet to file: %v\n")

		// DUMP END
		if total == recived {
			if s.Debug {
				fmt.Printf("Captured %v packets in %v\n", count, name)
			}
			count = 0
			if s.Ng {
				check(ngWriter.Flush(), "Error flushing file: %v\n")
			}
			if s.Zip {
				check(gzWriter.Close(), "Error zipping file: %v\n")
			}
			check(out.Close(), "Error closing file: %v\n")
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
		fmt.Printf("Capturing on %v:%v...\n", s.Iface, s.Port)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	handle_packets(packetSource, handle, s)
}