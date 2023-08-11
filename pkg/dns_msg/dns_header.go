package dns_msg

import (
	"encoding/binary"
	"fmt"
)

/*
   https://datatracker.ietf.org/doc/html/rfc1035#section-4
   https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1

                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                      ID                       |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    QDCOUNT                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    ANCOUNT                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    NSCOUNT                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                    ARCOUNT                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
type DNSHeader [12]byte

func (header *DNSHeader) SetID(value uint16) {
	binary.BigEndian.PutUint16(header[0:], value)
}

func (header *DNSHeader) GetID() uint16 {
	return binary.BigEndian.Uint16(header[0:])
}

func (header *DNSHeader) SetQR(value uint8) {
	//binary.BigEndian.PutUint16(header[2:], binary.BigEndian.Uint16(header[2:])|0x8000)

	header[2] |= value << 7
}

func (header *DNSHeader) GetQR() uint8 {
	return header[2] >> 7
}

func (header *DNSHeader) SetOpCode(value uint8) {
	header[2] |= (value & 0x0F) << 3
}

func (header *DNSHeader) GetOpCode() uint8 {
	return (header[2] >> 3) & 0x0F
}

func (header *DNSHeader) SetAA(value uint8) {
	header[2] |= (value & 0x01) << 2
}

func (header *DNSHeader) GetAA() uint8 {
	return (header[2] >> 2) & 0x01
}

func (header *DNSHeader) SetTC(value uint8) {
	header[2] |= (value & 0x01) << 1
}

func (header *DNSHeader) GetTC() uint8 {
	return (header[2] >> 1) & 0x01
}

func (header *DNSHeader) SetRD(value uint8) {
	header[2] |= (value & 0x01)
}

func (header *DNSHeader) GetRD() uint8 {
	return header[2] & 0x01
}

func (header *DNSHeader) SetRA(value uint8) {
	header[3] |= value << 7
}

func (header *DNSHeader) GetRA() uint8 {
	return header[3] >> 7
}

func (header *DNSHeader) GetRCode() uint8 {
	return header[3] & 0x0F
}

func (header *DNSHeader) GetZ() uint8 {
	return (header[3] >> 4) & 0x07
}

func (header *DNSHeader) SetQDCount(value uint16) {
	binary.BigEndian.PutUint16(header[4:], value)
}

func (header *DNSHeader) GetQDCount() uint16 {
	return binary.BigEndian.Uint16(header[4:])
}

func (header *DNSHeader) GetANCount() uint16 {
	return binary.BigEndian.Uint16(header[6:])
}

func (header *DNSHeader) GetNSCount() uint16 {
	return binary.BigEndian.Uint16(header[8:])
}

func (header *DNSHeader) SetARCount(value uint16) {
	binary.BigEndian.PutUint16(header[10:], value)
}

func (header *DNSHeader) GetARCount() uint16 {
	return binary.BigEndian.Uint16(header[10:])
}

func (header *DNSHeader) GetHeader() []byte {
	return header[0:]
}

func (header *DNSHeader) String() string {
	str := fmt.Sprintf("ID=%v, QR=%v, Opcode=%v, AA=%v, TC=%v, RD=%v, RA=%v, Z=%v, RCODE=%v\n",
		header.GetID(),
		header.GetQR(), header.GetOpCode(), header.GetAA(), header.GetTC(), header.GetRD(), header.GetRA(),
		header.GetZ(), header.GetRCode())
	str += fmt.Sprintf("QDCOUNT=%v, ANCOUNT=%v, NSCOUNT=%v, ARCOUNT=%v\n",
		header.GetQDCount(), header.GetANCount(), header.GetNSCount(), header.GetARCount())
	return str
}

func responseCode(code uint16) string {
	switch code {
	case 0:
		return "No error"
	case 1:
		return "Format error"
	case 2:
		return "Server failure"
	case 3:
		return "Name error"
	case 4:
		return "Not implemented"
	case 5:
		return "Refused"
	default:
		return "Unknown"
	}
}
