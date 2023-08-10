package dns_msg

import (
	"encoding/binary"
	"net"
)

/*
   https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3

                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                                               |
   /                                               /
   /                      NAME                     /
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                      TYPE                     |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     CLASS                     |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                      TTL                      |
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   RDLENGTH                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
   /                     RDATA                     /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

type Answer struct {
	buffer []byte
}

func (answer *Answer) GetName(offset int) (name string, length int) {
	begin_offset := offset

	for {
		labelLen := int(answer.buffer[offset])
		offset++

		if labelLen == 0 {
			break // 结束标志，域名解析完成
		}

		if labelLen&0xC0 == 0xC0 {
			// 如果是指针，则跳转到指针指向的位置继续解析
			pointerOffset := int(binary.BigEndian.Uint16([]byte{0, answer.buffer[offset] & 0x3F}))
			namePart, _ := answer.GetName(pointerOffset)
			name += namePart
			offset++
			break
		}

		label := string(answer.buffer[offset : offset+labelLen])
		name += label + "."
		offset += labelLen
	}

	// 如果 name 以 . 结尾，去掉这个点
	if name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	return name, offset - begin_offset
}

func (answer *Answer) GetType(offset int) (rType uint16, length int) {
	return binary.BigEndian.Uint16(answer.buffer[offset : offset+2]), 2
}

func (answer *Answer) GetClass(offset int) (rClass uint16, length int) {
	return binary.BigEndian.Uint16(answer.buffer[offset : offset+2]), 2
}

func (answer *Answer) GetTTL(offset int) (rTTL uint32, length int) {
	return binary.BigEndian.Uint32(answer.buffer[offset : offset+4]), 4
}

func (answer *Answer) GetDLen(offset int) (rDLen uint16, length int) {
	return binary.BigEndian.Uint16(answer.buffer[offset : offset+2]), 2
}

func (answer *Answer) GetData(offset int, rDLen uint16) []byte {
	return answer.buffer[offset : offset+int(rDLen)]
}

func parseIPFromRData(rdata []byte) net.IP {
	ip := make(net.IP, len(rdata))
	copy(ip, rdata)
	return ip
}
