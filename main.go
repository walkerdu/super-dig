package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

var (
	usage = `Usage: %s [options] Domain-Name
Options:
	-t, --type <A, NS, CNAME, ANY type Resource Records>
`
	Usage = func() {
		fmt.Printf(usage, os.Args[0])
	}
)

var (
	rrType     = flag.String("t", "A", "request RR type")
	domainName = ""
)

func main() {
	flag.Usage = Usage
	if len(os.Args) <= 1 {
		flag.Usage()
		os.Exit(1)
	}

	flag.Parse()

	// 输入参数中没有options的默认位URL参数，可以在任意位置
	for flag.NArg() > 0 {
		if len(domainName) == 0 {
			domainName = flag.Args()[0]
		} else {
			log.Printf("[WARN] ignore unkown params: %s", flag.Args()[0])
		}

		os.Args = flag.Args()[0:]
		flag.Parse()
	}

	if len(domainName) == 0 {
		log.Printf("[WARN] please input domain names")
		flag.Usage()
		return
	}

	nameserver := "8.8.8.8" // Google's public DNS server
	//nameserver = "119.29.29.29" // Tencent's public DNS server
	nameserver = "10.123.119.98"

	// Create UDP connection to DNS server
	conn, err := net.Dial("udp", nameserver+":53")
	if err != nil {
		log.Println("Error creating UDP connection:", err)
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Second * 10))

	// Construct DNS query
	query := makeDNSQuery(domainName)

	// Send DNS query
	_, err = conn.Write(query)
	if err != nil {
		log.Println("Error sending DNS query:", err)
		return
	}

	// Receive DNS response
	response := make([]byte, 1024*100)
	_, err = conn.Read(response)
	if err != nil {
		log.Println("Error receiving DNS response:", err)
		return
	}

	// Process and print DNS response
	parseDNSResponse(response)
}

func makeDNSQuery(domain string) []byte {
	// DNS query header
	queryID := uint16(rand.Int31n(65535)) // Use your own query ID
	flags := uint16(0x0100)               // Standard query
	qdCount := uint16(1)                  // Number of questions
	anCount := uint16(0)                  // Number of answers
	nsCount := uint16(0)                  // Number of authority records
	arCount := uint16(1)                  // Number of additional records

	// Construct DNS query packet using domain name
	queryName := appendDomainName(domain)

	queryData := make([]byte, 12+len(queryName)+4+1024) // 12 for header, 4 for type and class
	binary.BigEndian.PutUint16(queryData[0:], queryID)
	binary.BigEndian.PutUint16(queryData[2:], flags)
	binary.BigEndian.PutUint16(queryData[4:], qdCount)
	binary.BigEndian.PutUint16(queryData[6:], anCount)
	binary.BigEndian.PutUint16(queryData[8:], nsCount)
	binary.BigEndian.PutUint16(queryData[10:], arCount)

	queryType := uint16(1)  // A record type
	queryClass := uint16(1) // Internet class
	copy(queryData[12:], queryName)
	binary.BigEndian.PutUint16(queryData[12+len(queryName):], queryType)
	binary.BigEndian.PutUint16(queryData[12+len(queryName)+2:], queryClass)

	offset := 12 + len(queryName) + 4
	// 河北石家庄电信
	//offset = addEDNSClientSubnet(queryData, offset, net.ParseIP("27.128.190.0"), 0)

	// 河北石家庄联通
	offset = addEDNSClientSubnet(queryData, offset, net.ParseIP("45.119.68.0"), 0)
	return queryData[0:offset]
}

func appendDomainName(domain string) []byte {
	labels := strings.Split(domain, ".")
	var result []byte

	for _, label := range labels {
		result = append(result, byte(len(label))) // 添加标签长度
		result = append(result, []byte(label)...) // 添加标签内容
	}

	result = append(result, 0) // 结束标志
	return result
}

func parseDNSResponse(response []byte) {
	// DNS response header
	transactionID := binary.BigEndian.Uint16(response[0:2])
	flags := binary.BigEndian.Uint16(response[2:4])
	qdCount := binary.BigEndian.Uint16(response[4:6])
	anCount := binary.BigEndian.Uint16(response[6:8])
	nsCount := binary.BigEndian.Uint16(response[8:10])
	arCount := binary.BigEndian.Uint16(response[10:12])

	fmt.Printf("reponse:%02x\n", response[0:200])
	fmt.Println("Transaction ID:", transactionID)
	//fmt.Println("Flags:", flags)
	parseDNSFlags(flags)
	fmt.Println("Questions:", qdCount)
	fmt.Println("Answers:", anCount)
	fmt.Println("Authority Records:", nsCount)
	fmt.Println("Additional Records:", arCount)

	// Parse DNS answers, authority records, and additional records
	offset := 12 // Start after header
	for idx := uint16(0); idx < qdCount+anCount+nsCount+arCount; idx++ {
		if idx < qdCount {
			fmt.Println("----------------Query Section---------------")
			offset = parseQuerySection(response, offset)
		} else if idx < qdCount+anCount {
			fmt.Println("-----------Answer Records Section-----------")
			offset = parseAnswerSection(response, offset)
		} else if idx < qdCount+anCount+nsCount {
			fmt.Println("----------Authority Records Section---------")
		} else if idx < qdCount+anCount+nsCount+arCount {
			fmt.Println("----------Additional Records Section--------")
		}

	}
}

func parseDNSFlags(flags uint16) {
	fmt.Printf("Flags|Response: %v\n", (flags>>15)&1 == 1)
	fmt.Printf("Flags|Authoritative Answer: %v\n", (flags>>10)&1 == 1)
	fmt.Printf("Flags|Truncated: %v\n", (flags>>9)&1 == 1)
	fmt.Printf("Flags|Recursion Desired: %v\n", (flags>>8)&1 == 1)
	fmt.Printf("Flags|Recursion Available: %v\n", (flags>>7)&1 == 1)
	fmt.Printf("Flags|Response code: %s\n", responseCode(flags&0x0F))
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

func parseQuerySection(response []byte, offset int) int {
	name, offset := parseName(response, offset)
	rType := binary.BigEndian.Uint16(response[offset : offset+2])
	rClass := binary.BigEndian.Uint16(response[offset+2 : offset+4])

	fmt.Println("Name:", name)
	fmt.Println("Type:", rType)
	fmt.Println("Class:", rClass)

	return offset + 4
}

func parseAnswerSection(response []byte, offset int) int {
	name, offset := parseName(response, offset)
	rType := binary.BigEndian.Uint16(response[offset : offset+2])
	rClass := binary.BigEndian.Uint16(response[offset+2 : offset+4])
	rTTL := binary.BigEndian.Uint32(response[offset+4 : offset+8])
	rDLen := binary.BigEndian.Uint16(response[offset+8 : offset+10])
	rData := response[offset+10 : offset+10+int(rDLen)]

	fmt.Println("Name:", name)
	fmt.Println("Type:", rType)
	fmt.Println("Class:", rClass)
	fmt.Println("TTL:", rTTL)
	fmt.Println("Data Length:", rDLen)
	fmt.Println("Data:", parseIPFromRData(rData))

	return offset + 10 + int(rDLen)
}

func parseName(response []byte, offset int) (string, int) {
	var name string

	for {
		labelLen := int(response[offset])
		offset++

		if labelLen == 0 {
			break // 结束标志，域名解析完成
		}

		if labelLen&0xC0 == 0xC0 {
			// 如果是指针，则跳转到指针指向的位置继续解析
			pointerOffset := int(binary.BigEndian.Uint16([]byte{0, response[offset] & 0x3F}))
			namePart, _ := parseName(response, pointerOffset)
			name += namePart
			offset++
			break
		}

		label := string(response[offset : offset+labelLen])
		name += label + "."
		offset += labelLen
	}

	// 如果 name 以 . 结尾，去掉这个点
	if name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	return name, offset
}

func parseIPFromRData(rdata []byte) net.IP {
	ip := make(net.IP, len(rdata))
	copy(ip, rdata)
	return ip
}

func addEDNSClientSubnet(query []byte, offset int, clientIP net.IP, sourceNetmask int) int {
	// Set RR NAME (empty, as it's not required for EDNS options)
	query[offset] = 0x00
	offset++

	// Set RR Type = 41 (OPT)
	binary.BigEndian.PutUint16(query[offset:], 41)
	offset += 2

	// Set RR Class = 4096 (UDP Payload Size)
	binary.BigEndian.PutUint16(query[offset:], 4096)
	offset += 2

	// Set RR TTL = 0
	binary.BigEndian.PutUint32(query[offset:], 0)
	offset += 4

	// Set RR RDLEN = 8 bytes for EDNS Client Subnet option
	binary.BigEndian.PutUint16(query[offset:], 8)
	offset += 2

	// Set Option Code = 8 (EDNS Client Subnet)
	binary.BigEndian.PutUint16(query[offset:], 8)
	offset += 2

	// Set Option Length = 4 bytes
	binary.BigEndian.PutUint16(query[offset:], 4)
	offset += 2

	// IP Version (1 for IPv4, 2 for IPv6)
	query[offset] = 0x01
	offset++

	// Source Netmask
	query[offset] = byte(sourceNetmask)
	offset++

	// Scope Netmask (0 for IPv4, 0 for IPv6)
	query[offset] = 0x00
	offset++

	// Client IP address (4 bytes for IPv4, 16 bytes for IPv6)
	copy(query[offset:], clientIP)
	offset += len(clientIP)

	return offset
}
