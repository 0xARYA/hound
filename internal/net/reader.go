package net

import (
	"io"
)

type HandshakeReader struct {
	reader         io.Reader
	bytesRemaining int
}

func (reader *HandshakeReader) Read(p []byte) (int, error) {
	for reader.bytesRemaining == 0 {
		header, err := readRecordHeader(reader.reader)

		if err != nil {
			return 0, err
		}

		if header.contentType == 22 {
			reader.bytesRemaining = int(header.length)
		} else {
			_, copyError := io.CopyN(io.Discard, reader.reader, int64(header.length))

			if copyError != nil {
				return 0, copyError
			}
		}
	}

	if len(p) > reader.bytesRemaining {
		p = p[:reader.bytesRemaining]
	}

	bytesRead, err := reader.reader.Read(p)

	reader.bytesRemaining -= bytesRead

	return bytesRead, err
}

func (reader *HandshakeReader) ReadMessage() ([]byte, error) {
	var header [4]byte

	_, readError := io.ReadFull(reader, header[:])

	if readError != nil {
		return nil, readError
	}

	length := (uint32(header[1]) << 16) | (uint32(header[2]) << 8) | uint32(header[3])

	message := make([]byte, len(header)+int(length))

	copy(message, header[:])

	_, readError = io.ReadFull(reader, message[len(header):])

	if readError != nil {
		return nil, readError
	}

	return message, nil
}

func NewHandshakeReader(reader io.Reader) *HandshakeReader {
	return &HandshakeReader{reader: reader}
}
