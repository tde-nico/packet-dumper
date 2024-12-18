package main

import (
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type Writer interface {
	Write(p []byte) (n int, err error)
	Close() error
}

func encryptWriter(key []byte, writer io.Writer) (*cipher.StreamWriter, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	if _, err := writer.Write(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	return &cipher.StreamWriter{S: stream, W: writer}, nil
}

func init_writers(s *service, handle *pcap.Handle, name string) (Writer, *gzip.Writer, *pcapgo.NgWriter, *pcapgo.Writer, string) {
	var encrypter *cipher.StreamWriter
	var gzWriter *gzip.Writer
	var ngWriter *pcapgo.NgWriter
	var writer *pcapgo.Writer

	i := 0
	n := name
	parts := strings.SplitN(name, ".pcap", 2)
	parts[0] += "."
	parts[1] = ".pcap" + parts[1]
	for {
		if _, err := os.Stat(n); os.IsNotExist(err) {
			break
		}
		n = parts[0] + strconv.Itoa(i) + parts[1]
		i += 1
	}
	out, err := os.OpenFile(n, os.O_RDWR|os.O_CREATE, 0600)
	check(err, "Error opening %v out file: %v\n")

	if s.Enc {
		encrypter, err = encryptWriter(s.Key, out)
		check(err, "Error encrypting file: %v\n")
	}
	if s.Zip {
		if s.Enc {
			gzWriter = gzip.NewWriter(encrypter)
		} else {
			gzWriter = gzip.NewWriter(out)
		}
	}

	if s.Ng {
		if s.Zip {
			ngWriter, err = pcapgo.NewNgWriter(gzWriter, handle.LinkType())
		} else {
			if s.Enc {
				ngWriter, err = pcapgo.NewNgWriter(encrypter, handle.LinkType())
			} else {
				ngWriter, err = pcapgo.NewNgWriter(out, handle.LinkType())
			}
		}
		check(err, "Error creating file: %v\n")
	} else {
		if s.Zip {
			writer = pcapgo.NewWriter(gzWriter)
		} else {
			if s.Enc {
				writer = pcapgo.NewWriter(encrypter)
			} else {
				writer = pcapgo.NewWriter(out)
			}
		}
		err = writer.WriteFileHeader(uint32(handle.SnapLen()), handle.LinkType())
		check(err, "Error writing file header: %v\n")
	}

	if s.Enc {
		return encrypter, gzWriter, ngWriter, writer, n
	} else {
		return out, gzWriter, ngWriter, writer, n
	}
}
