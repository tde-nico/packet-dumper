package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

const settings = "settings.json"

var err_row int = -1

var (
	promisc bool = false
	err     error
)

type service struct {
	Port     string        `json:"port"`
	Rotation time.Duration `json:"rotation"`
	Iface    string        `json:"iface"`
	Dir      string        `json:"dir"`
	Name     string        `json:"name"`
	Format   string        `json:"format"`
	Snapslen int32         `json:"snapslen"`
	Filter   string        `json:"filter"`
	Zip      bool          `json:"zip"`
	Ng       bool          `json:"ng"`
	Enc      bool          `json:"enc"`
	Key      []byte        `json:"key"`
	Debug    bool          `json:"debug"`
}

type servicePtr struct {
	Port     *string        `json:"port"`
	Rotation *time.Duration `json:"rotation"`
	Iface    *string        `json:"iface"`
	Dir      *string        `json:"dir"`
	Name     *string        `json:"name"`
	Format   *string        `json:"format"`
	Snapslen *int32         `json:"snapslen"`
	Filter   *string        `json:"filter"`
	Zip      *bool          `json:"zip"`
	Ng       *bool          `json:"ng"`
	Enc      *bool          `json:"enc"`
	Key      *string        `json:"key"`
	Debug    *bool          `json:"debug"`
}

type services struct {
	Global   servicePtr   `json:"global"`
	Services []servicePtr `json:"services"`
}

func deploy(conf services, dry bool, no_sys bool) {
	servs := make([]service, len(conf.Services))
	for i := range conf.Services {
		apply_settings(&conf.Global, &conf.Services[i], &servs[i])

		if servs[i].Debug {
			fmt.Printf("Service: %v\n", i)
		}
		settings_setup(&servs[i], i)
		if servs[i].Dir != "" {
			check(os.MkdirAll(servs[i].Dir, 0600), "Error creating directory: %v\n")
		}
	}
	if dry {
		return
	}

	var s int
	if no_sys {
		s = 1
	}
	last := len(conf.Services) - s
	err_row = len(conf.Services) + 2
	clear_screen()
	for i := range conf.Services {
		if i != last {
			go capture(&servs[i], i+2-s)
		} else {
			capture(&servs[i], i+2-s)
		}
	}
	for {
		print_stats()
	}
}

// sudo ./godump -debug -G 60 -w "test_%Y-%m-%d_%H.%M.%S.pcap" -s 0 -i eth0 tcp and port 4444
func main() {
	var (
		s      service
		dry    bool
		no_sys bool
	)
	parse(&s, &dry, &no_sys)

	if _, err := os.Stat(settings); os.IsNotExist(err) || s.Iface != "" {
		if !dry {
			capture(&s, -1)
		}
		return
	}

	file, err := os.Open(settings)
	if err != nil {
		log.Fatalf("Error opening file: %v\n", err)
	}

	var config services
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		log.Fatalf("Error decoding JSON: %v\n", err)
	}
	file.Close()

	deploy(config, dry, no_sys)
}
