package dns_msg

import (
	"encoding/binary"
	"net"
)

/*
 .  RFC6891： Extension Mechanisms for DNS (EDNS0)
    https://www.rfc-editor.org/rfc/rfc6891
    +------------+--------------+------------------------------+
    | Field Name | Field Type   | Description                  |
    +------------+--------------+------------------------------+
    | NAME       | domain name  | MUST be 0 (root domain)      |
    | TYPE       | u_int16_t    | OPT (41)                     |
    | CLASS      | u_int16_t    | requestor's UDP payload size |
    | TTL        | u_int32_t    | extended RCODE and flags     |
    | RDLEN      | u_int16_t    | length of all RDATA          |
    | RDATA      | octet stream | {attribute,value} pairs      |
    +------------+--------------+------------------------------+

                +0 (MSB)                            +1 (LSB)
     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  0: |                          OPTION-CODE                          |
     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  2: |                         OPTION-LENGTH                         |
     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  4: |                                                               |
     /                          OPTION-DATA                          /
     /                                                               /
     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

    https://datatracker.ietf.org/doc/html/draft-vandergaast-edns-client-subnet-00#format
                +0 (MSB)                            +1 (LSB)
    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  0: |                          OPTION-CODE                          |
     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  2: |                         OPTION-LENGTH                         |
     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  4: |                            FAMILY                             |
     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  6: |          SOURCE NETMASK       |        SCOPE NETMASK          |
     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  7: |                           ADDRESS...                          /
     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
*/

type Additional struct {
	buffer []byte
}

func (additional *Additional) SetName(offset int) (length int) {
	additional.buffer[offset] = 0
	return 1
}

func (additional *Additional) SetType(offset int, rType uint16) (length int) {
	binary.BigEndian.PutUint16(additional.buffer[offset:], rType)
	return 2
}

func (additional *Additional) GetType(offset int) (rType uint16, length int) {
	return binary.BigEndian.Uint16(additional.buffer[offset : offset+2]), 2
}

func (additional *Additional) SetClass(offset int, rClass uint16) (length int) {
	binary.BigEndian.PutUint16(additional.buffer[offset:], rClass)
	return 2
}

func (additional *Additional) GetClass(offset int) (rClass uint16, length int) {
	return binary.BigEndian.Uint16(additional.buffer[offset : offset+2]), 2
}

func (additional *Additional) SetTTL(offset int, rTTL uint32) (length int) {
	binary.BigEndian.PutUint32(additional.buffer[offset:], rTTL)
	return 4
}

func (additional *Additional) GetTTL(offset int) (rTTL uint32, length int) {
	return binary.BigEndian.Uint32(additional.buffer[offset : offset+4]), 4
}

func (additional *Additional) SetDLen(offset int, rDLen uint16) (length int) {
	binary.BigEndian.PutUint16(additional.buffer[offset:], rDLen)
	return 2
}

func (additional *Additional) GetDLen(offset int) (rDLen uint16, length int) {
	return binary.BigEndian.Uint16(additional.buffer[offset : offset+2]), 2
}

func (additional *Additional) GetData(offset int, rDLen uint16) []byte {
	return additional.buffer[offset : offset+int(rDLen)]
}

func (additional *Additional) SetOptCode(offset int, optCode uint16) (length int) {
	binary.BigEndian.PutUint16(additional.buffer[offset:], optCode)
	return 2
}

func (additional *Additional) SetOptDLen(offset int, optDLen uint16) (length int) {
	binary.BigEndian.PutUint16(additional.buffer[offset:], optDLen)
	return 2
}

func (additional *Additional) SetClientSubnetOptFamily(offset int, family uint16) (length int) {
	binary.BigEndian.PutUint16(additional.buffer[offset:], family)
	return 2
}

func (additional *Additional) SetClientSubnetOptSourceNetMask(offset int, mask uint8) (length int) {
	additional.buffer[offset] = mask
	return 1
}

func (additional *Additional) SetClientSubnetOptScopeNetMask(offset int, mask uint8) (length int) {
	additional.buffer[offset] = mask
	return 1
}

func (additional *Additional) SetClientSubnetOptAddress(offset int, address []byte) (length int) {
	copy(additional.buffer[offset:], address)
	return len(address)
}

func (additional *Additional) AddEDNSClientSubnet(offset int, clientIP net.IP, sourceNetMaskLen uint8) int {
	// Set RR NAME (empty, as it's not required for EDNS options)
	offset += additional.SetName(offset)

	// Set RR Type = 41 (OPT)
	offset += additional.SetType(offset, 41)

	// Set RR Class = 4096 (UDP Payload Size)
	offset += additional.SetClass(offset, 4096)

	// Set RR TTL = 0
	offset += additional.SetTTL(offset, 0)

	subNetIpLen := sourceNetMaskLen / 8

	// Set RR RDLEN = (8 + SubNet IP Len )bytes for EDNS Client Subnet option
	offset += additional.SetDLen(offset, uint16(2+2+2+1+1+subNetIpLen))

	// Set Option Code = 8 (EDNS Client Subnet)
	offset += additional.SetOptCode(offset, 8)

	// Set Option Length = (4 + SubNet IP Len) bytes
	offset += additional.SetOptDLen(offset, uint16(2+2+subNetIpLen))

	// IP Version (1 for IPv4, 2 for IPv6)
	offset += additional.SetClientSubnetOptFamily(offset, 1)

	// Source Netmask
	offset += additional.SetClientSubnetOptSourceNetMask(offset, sourceNetMaskLen)

	// Scope Netmask (0 for IPv4, 0 for IPv6)
	offset += additional.SetClientSubnetOptScopeNetMask(offset, 0x00)

	clientIP = clientIP.To4()[0:subNetIpLen]

	// Client SubNet IP address (4 bytes for IPv4, 16 bytes for IPv6)
	offset += additional.SetClientSubnetOptAddress(offset, clientIP)

	return offset
}
