package houndHTTP2

import (
	"fmt"
	"strings"
)

type ParsedFrame struct {
	Type      string   `json:"type,omitempty"`
	StreamID  uint32   `json:"streamID,omitempty"`
	Flags     uint8    `json:"flags,omitempty"`
	Length    uint32   `json:"length,omitempty"`
	Payload   []byte   `json:"payload,omitempty"`
	Headers   []string `json:"headers,omitempty"`
	Settings  []string `json:"settings,omitempty"`
	Increment uint32   `json:"increment,omitempty"`
	Weight    int      `json:"weight,omitempty"`
	DependsOn int      `json:"dependsOn,omitempty"`
	Exclusive int      `json:"exclusive,omitempty"`
}

func getSettingsFingerprint(frames []ParsedFrame) string {
	var settingsFingerprint string

	mapping := map[string]string{
		"HEADER_TABLE_SIZE":      "1",
		"ENABLE_PUSH":            "2",
		"MAX_CONCURRENT_STREAMS": "3",
		"INITIAL_WINDOW_SIZE":    "4",
		"MAX_FRAME_SIZE":         "5",
		"MAX_HEADER_LIST_SIZE":   "6",
	}

	for _, parsedFrame := range frames {
		if parsedFrame.Type == "SETTINGS" {
			for _, setting := range parsedFrame.Settings {
				settingParts := strings.Split(setting, " = ")

				if len(settingParts) != 2 {
					return "ERROR"
				}

				settingsFingerprint += mapping[settingParts[0]] + ":" + settingParts[1] + ","
			}

			break
		}
	}

	return strings.TrimRight(settingsFingerprint, ",")
}

func getWindowUpdateFingerprint(frames []ParsedFrame) string {
	for _, parsedFrame := range frames {
		if parsedFrame.Type == "WINDOW_UPDATE" {
			return fmt.Sprintf("%d", parsedFrame.Increment)
		}
	}

	return "00"
}

func getPriorityFingerprint(frames []ParsedFrame) string {
	var priorityFingerprint string

	for _, parsedFrame := range frames {
		if parsedFrame.Type == "PRIORITY" {
			priorityFingerprint += fmt.Sprintf("%v:%v:%v:%v", parsedFrame.StreamID, parsedFrame.Exclusive, parsedFrame.DependsOn, parsedFrame.Weight)

			priorityFingerprint += ","
		}
	}

	if priorityFingerprint != "" {
		return strings.TrimRight(priorityFingerprint, ",")
	}

	return "0"
}

func getHeaderOrderFingerprint(parsedFrames []ParsedFrame) string {
	var headerOrderFingerprint string

	for _, parsedFrame := range parsedFrames {
		if parsedFrame.Type == "HEADERS" {
			for headerIndex, header := range parsedFrame.Headers {
				if strings.HasPrefix(header, ":") {
					headerOrderFingerprint += string(header[1])

					if headerIndex < 3 {
						headerOrderFingerprint += ","
					}
				}
			}

			break
		}
	}

	return headerOrderFingerprint
}

func Fingerprint(parsedFrames []ParsedFrame) string {
	var fingerprint string

	fingerprint += getSettingsFingerprint(parsedFrames) + "|"
	fingerprint += getWindowUpdateFingerprint(parsedFrames) + "|"
	fingerprint += getPriorityFingerprint(parsedFrames) + "|"
	fingerprint += getHeaderOrderFingerprint(parsedFrames)

	return fingerprint
}
