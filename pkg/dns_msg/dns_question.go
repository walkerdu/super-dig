package dns_msg

import (
	"encoding/binary"
	"strings"
)

/*
   https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2

                                   1  1  1  1  1  1
     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                                               |
   /                     QNAME                     /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     QTYPE                     |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     QCLASS                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

type Question struct {
	Data []byte
}

func (question *Question) AddQuestion(qName string, qType, qClass uint16) {
	labels := strings.Split(qName, ".")
	for _, label := range labels {
		question.Data = append(question.Data, byte(len(label))) // 添加标签长度
		question.Data = append(question.Data, []byte(label)...) // 添加标签内容
	}

	question.Data = append(question.Data, 0) // 结束标志

	offset := len(question.Data)
	question.Data = append(question.Data, []byte{0, 0, 0, 0}...)

	binary.BigEndian.PutUint16(question.Data[offset:], qType)
	binary.BigEndian.PutUint16(question.Data[offset+2:], qClass)
}

func (question *Question) GetQName(offset int) (name string, length int) {
	begin_offset := offset

	for {
		labelLen := int(question.Data[offset])
		offset++

		if labelLen == 0 {
			break // 结束标志，域名解析完成
		}

		if labelLen&0xC0 == 0xC0 {
			// 如果是指针，则跳转到指针指向的位置继续解析
			pointerOffset := int(binary.BigEndian.Uint16([]byte{0, question.Data[offset] & 0x3F}))
			namePart, _ := question.GetQName(pointerOffset)
			name += namePart
			offset++
			break
		}

		label := string(question.Data[offset : offset+labelLen])
		name += label + "."
		offset += labelLen
	}

	// 如果 name 以 . 结尾，去掉这个点
	if name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	return name, offset - begin_offset
}

func (question *Question) GetQType(offset int) (qType uint16, length int) {
	return binary.BigEndian.Uint16(question.Data[offset : offset+2]), 2
}

func (question *Question) GetQClass(offset int) (qClass uint16, length int) {
	return binary.BigEndian.Uint16(question.Data[offset : offset+2]), 2
}
