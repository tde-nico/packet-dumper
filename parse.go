package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func settings_setup(s *service) {
	s.Rotation *= time.Second
	if s.Ng {
		s.Fname += "ng"
	}
	if s.Zip {
		s.Fname += ".gz"
	}
	if s.Enc {
		s.Fname += ".aes"
	}
	if s.Snapslen <= 0 {
		s.Snapslen = 262144
	}
	if s.Filter == "" {
		s.Filter = "tcp and port " + s.Port
	}
	if !strings.Contains(s.Filter, "port") {
		s.Filter += " and port " + s.Port
	} else {
		words := strings.Split(s.Filter, " ")
		s.Port = words[len(words)-1]
	}

	if s.Debug {
		fmt.Printf("Port: %v\n", s.Port)
		fmt.Printf("Rotation: %v\n", s.Rotation)
		fmt.Printf("Interface: %v\n", s.Iface)
		fmt.Printf("Filename: %v\n", s.Fname)
		fmt.Printf("Snapshot length: %v\n", s.Snapslen)
		fmt.Printf("Filter: %v\n", s.Filter)
		fmt.Printf("Zip: %v\n", s.Zip)
		fmt.Printf("Pcapng: %v\n", s.Ng)
		fmt.Printf("Encryption: %v\n\n", s.Enc)
	}
}

func parse(ser *service) {
	var (
		h    bool
		help bool

		p uint
		G int64
		s int
	)

	flag.BoolVar(&h, "h", false, "Show help")
	flag.BoolVar(&help, "help", false, "Show help")

	flag.UintVar(&p, "p", 4444, "Port to capture")
	flag.Int64Var(&G, "G", 60, "Rotation time in seconds")
	flag.StringVar(&ser.Iface, "i", "eth0", "Interface to capture")
	flag.StringVar(&ser.Fname, "w", "pkts_%Y-%m-%d_%H.%M.%S.pcap", "Output filename")
	flag.IntVar(&s, "s", 262144, "Snapshot length")
	flag.BoolVar(&ser.Zip, "z", false, "set for compressed output")
	flag.BoolVar(&ser.Ng, "ng", false, "set for pcapng output")
	flag.BoolVar(&ser.Enc, "e", false, "set for encrypted output")
	flag.BoolVar(&ser.Debug, "debug", false, "Enanales debug mode")
	flag.Parse()

	if h || help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	ser.Port = strconv.Itoa(int(p))
	ser.Rotation = time.Duration(G)
	ser.Snapslen = int32(s)
	ser.Filter = strings.Join(flag.Args(), " ")

	settings_setup(ser)
}
