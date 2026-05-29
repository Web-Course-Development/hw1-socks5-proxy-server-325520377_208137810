package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"io"
	"os"
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

	if version != 0x05 {
		conn.Write([]byte{0x05, 0xFF})
		return
	}

	requiredMethod := byte(0x00) // no-auth by default
	if os.Getenv("PROXY_USER") != "" {
		requiredMethod = 0x02 // username/password
	}

	methodFound := false
	for _, method := range methods {
		if method == requiredMethod {
			methodFound = true
			break
		}
	}

	if !methodFound {
		conn.Write([]byte{0x05, 0xFF})
		return
	}

	conn.Write([]byte{0x05, requiredMethod})

	if requiredMethod == 0x02 {
		if !authenticateUserPass(conn) {
			return
		}
	}
}
	func authenticateUserPass(conn net.Conn) bool {
	header := make([]byte, 2)

	_, err := io.ReadFull(conn, header)
	if err != nil {
		log.Printf("failed to read auth header: %v", err)
		return false
	}

	version := header[0]
	usernameLen := int(header[1])

	if version != 0x01 {
		conn.Write([]byte{0x01, 0x01})
		return false
	}

	username := make([]byte, usernameLen)
	_, err = io.ReadFull(conn, username)
	if err != nil {
		log.Printf("failed to read username: %v", err)
		return false
	}

	passLenBuf := make([]byte, 1)
	_, err = io.ReadFull(conn, passLenBuf)
	if err != nil {
		log.Printf("failed to read password length: %v", err)
		return false
	}

	passwordLen := int(passLenBuf[0])
	password := make([]byte, passwordLen)

	_, err = io.ReadFull(conn, password)
	if err != nil {
		log.Printf("failed to read password: %v", err)
		return false
	}

	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if string(username) == expectedUser && string(password) == expectedPass {
		conn.Write([]byte{0x01, 0x00})
		return true
	}

	conn.Write([]byte{0x01, 0x01})
	return false
}
