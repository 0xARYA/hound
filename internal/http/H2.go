package houndHTTP

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	houndHTTP2 "github.com/0xARYA/hound/pkg/HTTP2"
)

type HTTP2FingerprintResponse struct {
	TLSFingerprint   string `json:"TLS"`
	HTTP2Fingerprint string `json:"HTTP2"`
	IP               string `json:"IP"`
}

func parseHTTP2(framer *http2.Framer, frameParseChannel chan houndHTTP2.ParsedFrame) {
	for {
		frame, readFrameError := framer.ReadFrame()

		if readFrameError != nil {
			if strings.Contains(readFrameError.Error(), "use of closed network connection") {
				return
			}

			log.Println("Error reading frame: ", readFrameError)

			return
		}

		parsedFrame := houndHTTP2.ParsedFrame{}

		parsedFrame.Type = frame.Header().Type.String()
		parsedFrame.StreamID = frame.Header().StreamID
		parsedFrame.Length = frame.Header().Length

		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			parsedFrame.Settings = []string{}

			frame.ForeachSetting(func(HTTP2Setting http2.Setting) error {
				setting := fmt.Sprintf("%q", HTTP2Setting)

				setting = strings.Replace(setting, "\"", "", -1)
				setting = strings.Replace(setting, "[", "", -1)
				setting = strings.Replace(setting, "]", "", -1)

				parsedFrame.Settings = append(parsedFrame.Settings, setting)

				return nil
			})

		case *http2.HeadersFrame:
			decoder := hpack.NewDecoder(4096, func(hf hpack.HeaderField) {})

			decoder.SetEmitEnabled(true)

			headers, decodeError := decoder.DecodeFull(frame.HeaderBlockFragment())

			if decodeError != nil {
				log.Println("Error Decoding Headers: ", decodeError)

				return
			}

			for _, header := range headers {
				parsedHeader := fmt.Sprintf("%q: %q", header.Name, header.Value)

				parsedHeader = strings.Trim(parsedHeader, "\"")
				parsedHeader = strings.Replace(parsedHeader, "\": \"", ": ", -1)

				parsedFrame.Headers = append(parsedFrame.Headers, parsedHeader)
			}

		case *http2.DataFrame:
			parsedFrame.Payload = frame.Data()

		case *http2.WindowUpdateFrame:
			parsedFrame.Increment = frame.Increment

		case *http2.PriorityFrame:
			parsedFrame.Weight = int(frame.PriorityParam.Weight + 1)
			parsedFrame.DependsOn = int(frame.PriorityParam.StreamDep)

			if frame.PriorityParam.Exclusive {
				parsedFrame.Exclusive = 1
			}
		}

		frameParseChannel <- parsedFrame
	}
}

func handleHTTP2(connection net.Conn, TLSFingerprint string) {
	framer := http2.NewFramer(connection, connection)

	framer.WriteSettings(
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1048576},
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 65536},
	)

	frameParseChannel := make(chan houndHTTP2.ParsedFrame)

	go parseHTTP2(framer, frameParseChannel)

	var parsedFrames []houndHTTP2.ParsedFrame
	var parsedFrame houndHTTP2.ParsedFrame

	for {
		parsedFrame = <-frameParseChannel

		parsedFrames = append(parsedFrames, parsedFrame)

		if parsedFrame.Type == "HEADERS" {
			break
		}
	}

	HTTP2Fingerprint := houndHTTP2.Fingerprint(parsedFrames)

	responseBody, _ := json.Marshal(HTTP2FingerprintResponse{
		TLSFingerprint:   TLSFingerprint,
		HTTP2Fingerprint: HTTP2Fingerprint,
		IP:               connection.RemoteAddr().String(),
	})

	responseContentLength := strconv.Itoa(len(responseBody))

	headerBuffer := bytes.NewBuffer([]byte{})
	headerEncoder := hpack.NewEncoder(headerBuffer)

	headerEncoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	headerEncoder.WriteField(hpack.HeaderField{Name: "server", Value: "github.com/0xARYA/hound"})
	headerEncoder.WriteField(hpack.HeaderField{Name: "content-length", Value: responseContentLength})
	headerEncoder.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"})

	writeHeadersError := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      parsedFrame.StreamID,
		BlockFragment: headerBuffer.Bytes(),
		EndHeaders:    true,
	})

	if writeHeadersError != nil {
		log.Println("Failed To Write Headers: ", writeHeadersError)

		return
	}

	framer.WriteData(parsedFrame.StreamID, true, responseBody)
}
