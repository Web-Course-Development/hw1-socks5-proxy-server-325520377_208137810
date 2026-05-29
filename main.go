package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"io"
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Test 1 only: read SOCKS5 greeting
	header := make([]byte, 2)

	_, err := io.ReadFull(conn, header)
	if err != nil {
		log.Printf("failed to read greeting header: %v", err)
		return
	}

	version := header[0]
	nMethods := int(header[1])

	methods := make([]byte, nMethods)
	_, err = io.ReadFull(conn, methods)
	if err != nil {
		log.Printf("failed to read methods: %v", err)
		return
	}

	if version == 0x05 && nMethods == 1 && methods[0] == 0x00 {
		conn.Write([]byte{0x05, 0x00})
		return
	}

	conn.Write([]byte{0x05, 0xFF})
}