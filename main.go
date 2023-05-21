package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
)

const DNSHeaderLength = 12

type DNSHeader struct {
	ID      uint16
	QR      uint16 // 1bit
	OPCODE  uint16 // 4bit
	AA      uint16 // 1bit
	TC      uint16 // 1bit
	RD      uint16 // 1bit
	RA      uint16 // 1bit
	Z       uint16 // 3bit, MUST be 0
	RCODE   uint16 // 4bit
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

func (h *DNSHeader) Pack() ([]byte, error) {
	// pack the bitfields
	var bitfield uint16 = 0
	bitfield |= h.QR << 15
	bitfield |= h.OPCODE << 11
	bitfield |= h.AA << 10
	bitfield |= h.TC << 9
	bitfield |= h.RD << 8
	bitfield |= h.RA << 7
	bitfield |= h.Z << 4
	bitfield |= h.TC << 3

	// assemble the header
	buf := make([]byte, DNSHeaderLength)
	binary.BigEndian.PutUint16(buf[0:], h.ID)
	binary.BigEndian.PutUint16(buf[2:], bitfield)
	binary.BigEndian.PutUint16(buf[4:], h.QDCOUNT)
	binary.BigEndian.PutUint16(buf[6:], h.ANCOUNT)
	binary.BigEndian.PutUint16(buf[8:], h.NSCOUNT)
	binary.BigEndian.PutUint16(buf[10:], h.ARCOUNT)
	return buf, nil
}

type DNSQuestion struct {
	QNAME  string
	QTYPE  uint16
	QCLASS uint16
}

func (q *DNSQuestion) Pack() ([]byte, error) {
	buf := make([]byte, 0, len(q.QNAME)+6)
	for _, label := range strings.Split(q.QNAME, ".") {
		length := len(label)
		if length > 63 {
			return nil, fmt.Errorf("label '%s' is too long", label)
		}
		buf = append(buf, byte(length))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0) // QNAME gets null terminated
	buf = binary.BigEndian.AppendUint16(buf, q.QTYPE)
	buf = binary.BigEndian.AppendUint16(buf, q.QTYPE)
	if len(buf) != len(q.QNAME)+6 {
		return nil, fmt.Errorf("buffer length is %d, expected %d", len(buf), len(q.QNAME)+5)
	}
	return buf, nil
}

func printBuf(buf []byte) {
	const separator = "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+"
	fmt.Println("                                1  1  1  1  1  1\n  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5")
	fmt.Println(separator)
	for i, b := range buf {
		var pattern string
		if i%2 == 0 {
			pattern = "| %d  %d  %d  %d  %d  %d  %d  %d "
		} else {
			pattern = " %d  %d  %d  %d  %d  %d  %d  %d |\n"
		}
		fmt.Printf(
			pattern,
			(b&0x80)>>7,
			(b&0x40)>>6,
			(b&0x20)>>5,
			(b&0x10)>>4,
			(b&0x08)>>3,
			(b&0x04)>>2,
			(b&0x02)>>1,
			(b & 0x01),
		)
		if i%4 == 3 {
			fmt.Println(separator)
		}
	}
	if len(buf)%2 == 1 {
		fmt.Printf("                        |\n")
	}
	if len(buf)%4 != 0 {
		fmt.Println(separator)
	}
}

func generateID() uint16 {
	buf := make([]byte, 2)
	if n, err := rand.Read(buf); err != nil || n != 2 {
		panic("unable to generate 2 bytes of random bits")
	}
	return binary.BigEndian.Uint16(buf)
}

func main() {
	query := os.Args[1]
	header := DNSHeader{
		ID:      generateID(),
		QR:      0,
		OPCODE:  0,
		AA:      0,
		TC:      0,
		RD:      1,
		RA:      0,
		Z:       0,
		RCODE:   0,
		QDCOUNT: 1,
		ANCOUNT: 0,
		NSCOUNT: 0,
		ARCOUNT: 0,
	}
	packet, err := header.Pack()
	if err != nil {
		panic(fmt.Errorf("unable to pack header: %w", err))
	}

	question := DNSQuestion{
		QNAME:  query,
		QTYPE:  1,
		QCLASS: 1,
	}
	buf, err := question.Pack()
	if err != nil {
		panic(fmt.Errorf("unable to pack question: %w", err))
	}

	packet = append(packet, buf...)
	if len(packet) != DNSHeaderLength+len(query)+6 {
		panic("unexpected packet length")
	}
	printBuf(packet)

	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		panic(fmt.Errorf("unable to dial dns server: %w", err))
	}
	n, err := conn.Write(packet)
	if err != nil {
		panic(fmt.Errorf("error writing request to network: %w", err))
	} else if n != len(packet) {
		panic("unable to write full request")
	}

	buf = make([]byte, 512)
	n, err = conn.Read(buf)
	if err != nil {
		panic(fmt.Errorf("error reading response from network: %w", err))
	}
	printBuf(buf[:n])
}
