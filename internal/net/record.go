package houndNet

import "io"

type recordHeader struct {
	contentType uint8
	length      uint16
}

func readRecordHeader(reader io.Reader) (recordHeader, error) {
	var buffer [5]byte

	_, readError := io.ReadFull(reader, buffer[:])

	if readError != nil {
		return recordHeader{}, readError
	}

	return recordHeader{
		contentType: buffer[0],
		length:      (uint16(buffer[3]) << 8) | uint16(buffer[4]),
	}, nil
}
