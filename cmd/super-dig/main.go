package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/walkerdu/super-dig/configs"
	dnsMsg "github.com/walkerdu/super-dig/pkg/dns_msg"
)

var (
	usage = `Usage: %s [options] Domain-Name
Options:
	-t, --type <A, NS, CNAME, ANY type Resource Records>
	-f, --subnet_file <ip region file, for DNS client subnet>
	-ns <name server>
	--ns_file <name server file>
`
	Usage = func() {
		fmt.Printf(usage, os.Args[0])
	}
)

var (
	rrType         = flag.String("t", "A", "request RR type")
	nameServer     = flag.String("ns", "8.8.8.8", "name server")
	ipRegionFile   = flag.String("f", "", "ip region file")
	nameServerFile = flag.String("ns_file", "", "name server")
	domainName     = ""
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

	var ipRegions []configs.IPRegion
	if *ipRegionFile != "" {
		ipRegions = parseIPRegionFile(*ipRegionFile)
	}

	//nameserver := "8.8.8.8" // Google's public DNS server
	//nameserver = "208.67.222.222" // OpenDNS Server

	// Create UDP connection to DNS server
	conn, err := net.Dial("udp", *nameServer+":53")
	if err != nil {
		log.Println("Error creating UDP connection:", err)
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Second * 10))

	// 如果没有subnet文件，默认只看本机dig的结果
	if len(ipRegions) == 0 {
		ipRegions = append(ipRegions, configs.IPRegion{
			IPs: []string{""},
		})
	}

	for _, ipRegion := range ipRegions {
		for _, ip := range ipRegion.IPs {
			// Construct DNS query
			query := makeDNSQuery(domainName, ip)

			// Send DNS query
			_, err = conn.Write(query)
			if err != nil {
				log.Println("Error sending DNS query:", err)
				return
			}

			// Receive DNS response
			response := make([]byte, 1024*100)
			resBytes, err := conn.Read(response)
			if err != nil {
				log.Println("Error receiving DNS response:", err)
				return
			}

			// Process and print DNS response
			parseDNSResponse(response[0:resBytes])

			// 控制频率
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func parseIPRegionFile(ipRegionFile string) []configs.IPRegion {
	jsonFile, err := os.Open(ipRegionFile)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var ipRegions []configs.IPRegion
	err = json.Unmarshal(byteValue, &ipRegions)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	return ipRegions
}

func makeDNSQuery(domain string, clientSubnet string) []byte {
	var dnsHeader dnsMsg.DNSHeader

	// DNS query header
	dnsHeader.SetID(uint16(rand.Int31n(65535))) // Use your own query ID
	dnsHeader.SetQR(0)                          // Standard query
	dnsHeader.SetRD(1)                          // Recusive Desired
	dnsHeader.SetQDCount(1)                     // Number of questions

	// Construct DNS query packet using domain name
	var dnsQuestion dnsMsg.Question
	dnsQuestion.AddQuestion(domain, 1, 1)

	queryData := append(dnsHeader.GetHeader(), dnsQuestion.Data...)

	if clientSubnet != "" {
		dnsAdditional := dnsMsg.Additional{
			Data: make([]byte, 1024),
		}

		dnsHeader.SetARCount(1) // Number of additional records

		queryData = append(dnsHeader.GetHeader(), dnsQuestion.Data...)
		offset := dnsAdditional.AddEDNSClientSubnet(0, net.ParseIP(clientSubnet), 24)
		queryData = append(queryData, dnsAdditional.Data[0:offset]...)
	}

	fmt.Printf("Request:%02x\n", queryData)
	fmt.Println("Request Header\n", &dnsHeader)

	return queryData
}

func parseDNSResponse(response []byte) {
	fmt.Printf("Reponse:%02x\n", response)

	// DNS response header
	dnsHeader := dnsMsg.DNSHeader(response)
	fmt.Println("Reponse header:", &dnsHeader)

	qdCount := dnsHeader.GetQDCount()
	anCount := dnsHeader.GetANCount()
	nsCount := dnsHeader.GetNSCount()
	arCount := dnsHeader.GetARCount()

	// Parse DNS answers, authority records, and additional records
	offset := len(dnsHeader) // Start after header
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

func parseQuerySection(response []byte, offset int) int {
	dnsQuestion := dnsMsg.Question{
		Data: response,
	}

	name, length := dnsQuestion.GetQName(offset)
	offset += length

	rType, length := dnsQuestion.GetQType(offset)
	offset += length

	rClass, length := dnsQuestion.GetQClass(offset)
	offset += length

	fmt.Println("Name:", name)
	fmt.Println("Type:", rType)
	fmt.Println("Class:", rClass)

	return offset
}

func parseAnswerSection(response []byte, offset int) int {
	dnsAnswer := dnsMsg.Answer{
		Data: response,
	}

	name, length := dnsAnswer.GetName(offset)
	offset += length

	rType, length := dnsAnswer.GetType(offset)
	offset += length

	rClass, length := dnsAnswer.GetClass(offset)
	offset += length

	rTTL, length := dnsAnswer.GetTTL(offset)
	offset += length

	rDLen, length := dnsAnswer.GetDLen(offset)
	offset += length

	rData := dnsAnswer.GetData(offset, rDLen)

	fmt.Println("Name:", name)
	fmt.Println("Type:", rType)
	fmt.Println("Class:", rClass)
	fmt.Println("TTL:", rTTL)
	fmt.Println("Data Length:", rDLen)
	fmt.Println("Data:", dnsMsg.ParseIPFromRData(rData))

	return offset + int(rDLen)
}
