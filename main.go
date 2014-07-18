package main

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"flag"
	"log"
	"net"
	"sync"

	"code.google.com/p/go.crypto/pbkdf2"
)

var (
	flagRemote  = flag.String("remote", "localhost:1194", "Remote addr to connect to.")
	flagLocal   = flag.String("local", ":11194", "Local addr to listen to.")
	flagKey     = flag.String("key", "20121221", "Key to obfuscate the packet.")
	flagServer  = flag.Bool("server", false, "Server or client.")
	flagVerbose = flag.Bool("verbose", false, "Enable debug messages.")

	obfuscator cipher.Block
)

const udpMaxPacketSize = 65535

type connPair struct {
	IncomingAddr *net.UDPAddr
	OutgoingConn *net.UDPConn
}

func initCipher() {
	key := pbkdf2.Key([]byte(*flagKey), []byte("go-udpforward"), 4096, 24, sha1.New)
	var err error
	obfuscator, err = des.NewTripleDESCipher(key)
	check(err)
}

func main() {
	flag.Parse()
	initCipher()

	laddr, err := net.ResolveUDPAddr("udp", *flagLocal)
	check(err)
	raddr, err := net.ResolveUDPAddr("udp", *flagRemote)
	check(err)

	listener, err := net.ListenUDP("udp", laddr)
	check(err)
	buf := make([]byte, udpMaxPacketSize)
	connmap := make(map[string]connPair)
	mu := sync.Mutex{}
	for {
		n, local, err := listener.ReadFromUDP(buf)
		check(err)
		_, ok := connmap[local.String()]
		if !ok {
			outgoing, err := net.DialUDP("udp", nil, raddr)
			check(err)
			log.Println("Incoming connection from ", local.String())
			log.Println("Outgoing connection from ", outgoing.LocalAddr(), "to", outgoing.RemoteAddr())
			go func(laddr *net.UDPAddr, outgoing *net.UDPConn) {
				buf := make([]byte, udpMaxPacketSize)
				for {
					n, err := outgoing.Read(buf)
					if err != nil {
						break
					}
					if *flagVerbose {
						log.Println("Message from remote, writing to", laddr)
					}
					if *flagServer {
						obfuscator.Encrypt(buf[:n], buf[:n])
					} else {
						obfuscator.Decrypt(buf[:n], buf[:n])
					}
					_, err = listener.WriteToUDP(buf[:n], laddr)
					if err != nil {
						continue
					}
				}
				log.Println("Releasing connection for", local)
				mu.Lock()
				delete(connmap, local.String())
				mu.Unlock()
			}(local, outgoing)
			mu.Lock()
			connmap[local.String()] = connPair{local, outgoing}
			mu.Unlock()
		}
		outgoing := connmap[local.String()].OutgoingConn
		if *flagVerbose {
			log.Println("Forwarding packet to", outgoing.RemoteAddr())
		}
		if *flagServer {
			obfuscator.Decrypt(buf[:n], buf[:n])
		} else {
			obfuscator.Encrypt(buf[:n], buf[:n])
		}
		_, err = outgoing.Write(buf[:n])
		check(err)
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
