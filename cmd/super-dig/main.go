package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/walkerdu/super-dig/configs"
	dnsMsg "github.com/walkerdu/super-dig/pkg/dns_msg"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	usage = `Usage: %s [options] Domain-Name
Options:
	-t, --type <A, NS, CNAME, ANY type Resource Records>
	-f, --subnet_file <ip region file, for DNS client subnet>
	-ns <name server>
	--ns_file <name server file>
	--log_level <zap log level>
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
	logLevel       = flag.Int("log_level", 0, "zap log level, default info")
	domainName     = ""
	logger         *zap.Logger
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
			panic(fmt.Sprintf("ignore unkown params: %s", flag.Args()[0]))
		}

		os.Args = flag.Args()[0:]
		flag.Parse()
	}

	// 初始化日志
	config := zap.Config{
		Level:            zap.NewAtomicLevelAt(zapcore.Level(*logLevel)),
		Encoding:         "console",                         // 使用默认的 console 编码器
		EncoderConfig:    zap.NewDevelopmentEncoderConfig(), // 使用开发环境的默认编码器配置
		OutputPaths:      []string{"stdout"},                // 输出到标准输出
		ErrorOutputPaths: []string{"stderr"},                // 错误输出到标准错误输出
	}

	loggerIns, err := config.Build()
	if err != nil {
		panic("无法创建日志记录器")
	}
	defer loggerIns.Sync()
	logger = loggerIns

	if len(domainName) == 0 {
		logger.Error("[WARN] please input domain names")
		flag.Usage()
		return
	}

	var ipRegions []configs.IPRegion
	if *ipRegionFile != "" {
		ipRegions = parseIPRegionFile(*ipRegionFile)
	}

	// 如果没有subnet文件，默认只看本机dig的结果
	if len(ipRegions) == 0 {
		ipRegions = append(ipRegions, configs.IPRegion{
			IPs: []string{""},
		})
	}

	var nsList []configs.DNS
	if *nameServerFile != "" {
		nsList = parseNameServerFile(*nameServerFile)
	}

	// 没有指定用默认的nameserver
	if len(nsList) == 0 {
		nsList = append(nsList, configs.DNS{
			Nameserver: *nameServer,
		})
	}

	idx := 0
	nsIdx := 0
	var conn net.Conn
	rr2RegionMap := make(map[string]map[string]map[string]string)
	for _, ipRegion := range ipRegions {
		for _, ip := range ipRegion.IPs {
			// 每50个请求切换一下nameserver
			if idx%50 == 0 {
				// 释放上一个conn
				if conn != nil {
					conn.Close()
				}

				ns := nsList[nsIdx%len(nsList)]
				nsIdx += 1

				// Create UDP connection to DNS server
				var err error
				conn, err = net.Dial("udp", ns.Nameserver+":53")
				if err != nil {
					logger.Fatal("Error creating UDP connection", zap.Error(err))
				}

				logger.Debug("switch to DNS", zap.String("nameserver", ns.Nameserver), zap.Int("port", 53))
				conn.SetDeadline(time.Now().Add(time.Second * 10))
			}

			idx += 1

			// Construct DNS query
			query := makeDNSQuery(domainName, ip)

			// Send DNS query
			_, err := conn.Write(query)
			if err != nil {
				logger.Fatal("Error sending DNS query", zap.Error(err))
			}

			// Receive DNS response
			response := make([]byte, 1024*100)
			resBytes, err := conn.Read(response)
			if err != nil {
				logger.Fatal("Error receiving DNS response", zap.Error(err))
			}

			// Process and print DNS response
			aRRs := parseDNSResponse(response[0:resBytes])

			// 汇总结果
			sort.Strings(aRRs)
			aStr := strings.Join(aRRs, ",")

			province := ipRegion.Province
			if ipRegion.Province == "0" {
				province = ipRegion.Country
			}

			if regionInfo, ok := rr2RegionMap[aStr]; !ok {
				rr2RegionMap[aStr] = make(map[string]map[string]string)
				rr2RegionMap[aStr][ipRegion.ISP] = make(map[string]string)
				rr2RegionMap[aStr][ipRegion.ISP][province] = ipRegion.Country
			} else {
				if _, ok := regionInfo[ipRegion.ISP]; !ok {
					regionInfo[ipRegion.ISP] = make(map[string]string)
					regionInfo[ipRegion.ISP][province] = ipRegion.Country
				} else {
					regionInfo[ipRegion.ISP][province] = ipRegion.Country
				}
			}

			// 控制频率
			time.Sleep(5 * time.Millisecond)
		}
	}

	prettyStatistic(rr2RegionMap)
}

func parseNameServerFile(nsFile string) []configs.DNS {
	jsonFile, err := os.Open(nsFile)
	if err != nil {
		logger.Fatal("parseNameServerFile failed", zap.Error(err))
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var nsList []configs.DNS
	err = json.Unmarshal(byteValue, &nsList)
	if err != nil {
		logger.Fatal("parseNameServerFile failed", zap.Error(err))
	}

	return nsList
}

func parseIPRegionFile(ipRegionFile string) []configs.IPRegion {
	jsonFile, err := os.Open(ipRegionFile)
	if err != nil {
		logger.Fatal("parseIPRegionFile failed", zap.Error(err))
	}
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	var ipRegions []configs.IPRegion
	err = json.Unmarshal(byteValue, &ipRegions)
	if err != nil {
		logger.Fatal("parseIPRegionFile failed", zap.Error(err))
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

	logger.Debug(fmt.Sprintf("Request:%02x", queryData))
	logger.Debug(fmt.Sprintf("Request Header", &dnsHeader))

	return queryData
}

func parseDNSResponse(response []byte) []string {
	logger.Debug(fmt.Sprintf("Reponse:%02x\n", response))

	// DNS response header
	dnsHeader := dnsMsg.DNSHeader(response)
	logger.Debug(fmt.Sprintf("Reponse header:%s", &dnsHeader))

	qdCount := dnsHeader.GetQDCount()
	anCount := dnsHeader.GetANCount()
	nsCount := dnsHeader.GetNSCount()
	arCount := dnsHeader.GetARCount()

	var aRRs []string

	// Parse DNS answers, authority records, and additional records
	offset := len(dnsHeader) // Start after header
	for idx := uint16(0); idx < qdCount+anCount+nsCount+arCount; idx++ {
		if idx < qdCount {
			logger.Debug("----------------Query Section---------------")
			offset = parseQuerySection(response, offset)
		} else if idx < qdCount+anCount {
			logger.Debug("-----------Answer Records Section-----------")
			var rType uint16
			var rData []byte
			rType, rData, offset = parseAnswerSection(response, offset)
			if rType == 1 {
				aRRs = append(aRRs, dnsMsg.ParseIPFromRData(rData).String())
			}
		} else if idx < qdCount+anCount+nsCount {
			logger.Debug("----------Authority Records Section---------")
		} else if idx < qdCount+anCount+nsCount+arCount {
			logger.Debug("----------Additional Records Section--------")
		}
	}

	return aRRs
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

	logger.Debug(fmt.Sprintf("Name:%s", name))
	logger.Debug(fmt.Sprintf("Type:%s", rType))
	logger.Debug(fmt.Sprintf("Class:%s", rClass))

	return offset
}

func parseAnswerSection(response []byte, offset int) (uint16, []byte, int) {
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

	logger.Debug(fmt.Sprintf("Name:%s", name))
	logger.Debug(fmt.Sprintf("Type:%s", rType))
	logger.Debug(fmt.Sprintf("Class:%s", rClass))
	logger.Debug(fmt.Sprintf("TTL:%s", rTTL))
	logger.Debug(fmt.Sprintf("Data Length:%s", rDLen))
	logger.Debug(fmt.Sprintf("Data:%s", dnsMsg.ParseIPFromRData(rData)))

	return rType, rData, offset + int(rDLen)
}

func chineseCharCount(str string) int {
	count := 0
	for _, runeValue := range str {
		if utf8.RuneLen(runeValue) > 1 {
			count++
		}
	}
	return count
}

func prettyStatistic(aRRs map[string]map[string]map[string]string) {
	newLineStr := strings.Repeat("-", 30)
	fmt.Printf("|%s---%s---%s|\n", newLineStr, newLineStr, newLineStr)
	fmt.Printf("|%-30s | %-30s | %-30s|\n", "Local Subnet", "ISP", "Records A")
	fmt.Printf("|%s---%s---%s|\n", newLineStr, newLineStr, newLineStr)

	for ips, regions := range aRRs {
		ipList := strings.Split(ips, ",")

		ipLines := 0
		ispLen := 0

		// 按ISP聚合输出
		for isp, iInfo := range regions {
			ispLen += 1

			// 同一个A记录下，同一个ISP下，把所有Country+Province聚合
			var provinceList []string
			for province, pInfo := range iInfo {
				if province == pInfo && pInfo != "中国" {
					province = ""
				}

				provinceList = append(provinceList, pInfo+" "+province)
			}

			// 计算该ISP下，Country+Province，IP，ISP最大的行数
			thisIpMaxLines := 0

			ipRemainLen := 0
			if ipLines == 0 {
				// ip全部输出后，不再考虑ip占用的行数
				ipRemainLen = len(ipList)
			}

			if ipRemainLen > len(provinceList) {
				thisIpMaxLines = ipRemainLen
			} else {
				thisIpMaxLines = len(provinceList)
			}

			// 开始输出该ISP，应该输出的所有行
			var ip string
			var province string
			for loop_i := 0; loop_i < thisIpMaxLines; loop_i++ {
				if ipLines < ipRemainLen {
					ip = ipList[loop_i]
					ipLines += 1
				} else {
					ip = ""
				}

				if loop_i < len(provinceList) {
					province = provinceList[loop_i]
				} else {
					province = ""
				}

				if loop_i > 0 {
					isp = ""
				}

				provinceLen := 30 - chineseCharCount(province)
				ispLen := 30 - chineseCharCount(isp)
				fmt.Printf("|%-*s | %-*s | %-30s|\n", provinceLen, province, ispLen, isp, ip)
			}

			if ispLen < len(regions) {
				fmt.Printf("|%s---%s-| %-30s|\n", newLineStr, newLineStr, "")
			}
		}

		fmt.Printf("|%s---%s---%s|\n", newLineStr, newLineStr, newLineStr)
	}
}
