package configs

type IPRegion struct {
	Country  string   `json:"country"`
	Province string   `json:"province"`
	ISP      string   `json:"isp"`
	IPs      []string `json:"ips"`
}

type DNS struct {
	Nameserver string `json:"nameserver"`
	Desc       string `json:"desc"`
}
