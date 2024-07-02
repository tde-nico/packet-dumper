package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func apply[T any](g *T, sp *T, s *T) {
	if sp != nil {
		*s = *sp
	} else if g != nil {
		*s = *g
	}
}

func apply_settings(g, sp *servicePtr, s *service) {
	var g_key, sp_key *[]byte
	var tmp_g_key, tmp_sp_key []byte

	if g.Key != nil {
		tmp_g_key = []byte(*g.Key)
		g_key = &tmp_g_key
	}
	if sp.Key != nil {
		tmp_sp_key = []byte(*sp.Key)
		sp_key = &tmp_sp_key
	}

	apply(g.Port, sp.Port, &s.Port)
	apply(g.Rotation, sp.Rotation, &s.Rotation)
	apply(g.Iface, sp.Iface, &s.Iface)
	apply(g.Dir, sp.Dir, &s.Dir)
	apply(g.Name, sp.Name, &s.Name)
	apply(g.Format, sp.Format, &s.Format)
	apply(g.Snapslen, sp.Snapslen, &s.Snapslen)
	apply(g.Filter, sp.Filter, &s.Filter)
	apply(g.Zip, sp.Zip, &s.Zip)
	apply(g.Ng, sp.Ng, &s.Ng)
	apply(g.Enc, sp.Enc, &s.Enc)
	apply(g_key, sp_key, &s.Key)
	apply(g.Debug, sp.Debug, &s.Debug)
}

func settings_setup(s *service, id int) {
	var format *string
	if id >= 0 {
		s.Format += ".pcap"
		format = &s.Format
	} else {
		format = &s.Name
	}
	if s.Ng {
		*format += "ng"
	}
	if s.Zip {
		*format += ".gz"
	}
	if s.Enc {
		*format += ".aes"
	}
	s.Rotation *= time.Second
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
	if id >= 0 {
		s.Dir += "/service" + strconv.Itoa(id)
		s.Name = s.Dir + "/" + s.Name + "_" + *format
	}

	if len(s.Key) > 16 {
		s.Key = s.Key[:16]
	} else if len(s.Key) < 16 {
		for len(s.Key) < 16 {
			s.Key = append(s.Key, 0)
		}
	}

	if s.Debug {
		fmt.Printf("Port: %v\n", s.Port)
		fmt.Printf("Rotation: %v\n", s.Rotation)
		fmt.Printf("Interface: %v\n", s.Iface)
		fmt.Printf("Directory: %v\n", s.Dir)
		fmt.Printf("Name: %v\n", s.Name)
		fmt.Printf("Format: %v\n", s.Format)
		fmt.Printf("Snapshot length: %v\n", s.Snapslen)
		fmt.Printf("Filter: %v\n", s.Filter)
		fmt.Printf("Zip: %v\n", s.Zip)
		fmt.Printf("Pcapng: %v\n", s.Ng)
		fmt.Printf("Encryption: %v\n", s.Enc)
		fmt.Printf("Key: %v\n", s.Key)
		fmt.Printf("\n")
	}
}

func parse(ser *service, dry, no_sys *bool) {
	var (
		h    bool
		help bool

		p uint
		G int64
		s int
		k string
	)

	flag.BoolVar(&h, "h", false, "Show help")
	flag.BoolVar(&help, "help", false, "Show help")
	flag.BoolVar(dry, "dry-run", false, "Dry run")
	flag.BoolVar(no_sys, "no-sys", false, "No system stats print (only multi service)")
	flag.BoolVar(&INLINE, "inline", false, "Inline prints")

	flag.UintVar(&p, "p", 4444, "Port to capture")
	flag.Int64Var(&G, "G", 60, "Rotation time in seconds")
	flag.StringVar(&ser.Iface, "i", "", "Interface to capture")
	flag.StringVar(&ser.Name, "w", "pkts_%Y-%m-%d_%H-%M-%S.pcap", "Output filename")
	flag.IntVar(&s, "s", 262144, "Snapshot length")
	flag.BoolVar(&ser.Zip, "z", false, "set for compressed output")
	flag.BoolVar(&ser.Ng, "ng", false, "set for pcapng output")
	flag.StringVar(&k, "k", "", "set for encrypted output")
	flag.BoolVar(&ser.Debug, "debug", false, "Enanales debug mode")
	flag.Parse()

	if h || help {
		flag.PrintDefaults()
		os.Exit(0)
	}

	ser.Key = []byte(k)
	if len(ser.Key) > 0 {
		ser.Enc = true
	}

	ser.Port = strconv.Itoa(int(p))
	ser.Rotation = time.Duration(G)
	ser.Snapslen = int32(s)
	ser.Filter = strings.Join(flag.Args(), " ")

	settings_setup(ser, -1)
}
