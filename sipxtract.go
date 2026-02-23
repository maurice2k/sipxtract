// sipxtract is used to extract SIP calls (SIP packets along with it's RTP media
// packets) from a PCAP source.
//
// Copyright 2022-2025 Moritz Fain
// Moritz Fain <moritz@fain.io>
//
// Source available at github.com/maurice2k/sipxtract,
// licensed under the MIT license (see LICENSE file).

package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/jessevdk/go-flags"
)

type callInfo struct {
	packets           int
	last              time.Time
	lastSipPacket     *layers.SIP
	started           time.Time
	startedWithInvite bool
	finished          time.Time
	rtpPairs          int
	ackPending        bool
	ackSeen           bool
	doneCounted       bool
	rtpIPs            map[string]bool
}

type packetType uint16

const (
	packetSIP packetType = iota + 1
	packetRTP
)

var VERSION = "1.1.0"

var verbosity int = 0

var mainOpts struct {
	PcapIn      string `long:"in" description:"Source PCAP file (default: STDIN)" default:""`
	PcapOut     string `long:"out" description:"Output PCAP file (default: STDOUT)" default:""`
	SipPorts    []int  `short:"p" long:"port" description:"SIP port filter (multiple ports allowed)" default:"5060"`
	SkipRtp     bool   `long:"skip-rtp" description:"Skip RTP media packets"`
	RtpTail     int    `long:"rtp-tail" description:"Seconds of RTP to capture after call ends" default:"10"`
	RtpFilterIP bool   `long:"rtp-filter-ip" description:"Filter RTP by IPs from SDP connection lines"`
	FullScan    bool   `long:"full-scan" description:"Do a full scan even though given calls seem to be finished"`
	Verbose     []bool `short:"v" long:"verbose" description:"Show verbose information"`
	Version     bool   `long:"version" description:"Show sipxtract version"`
	Args        struct {
		CallIds []string `positional-arg-name:"Call-Id" description:"SIP Call-Id header value" required:"yes"`
	} `positional-args:"yes"`
}

func main() {
	// parse flags and arguments
	parser := flags.NewParser(&mainOpts, flags.HelpFlag|flags.PassAfterNonOption)
	_, err := parser.Parse()

	if mainOpts.Version {
		fmt.Println(VERSION)
		os.Exit(0)
	}

	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			// normal help behaviour
		} else {
			fmt.Println("Usage error:", err)
			fmt.Println()
		}
		parser.WriteHelp(os.Stdout)
		os.Exit(1)
	}

	verbosity = len(mainOpts.Verbose)

	// initialize lookups
	sipPorts := make(map[int]bool)
	for _, sipPort := range mainOpts.SipPorts {
		sipPorts[sipPort] = true
	}

	callIds := make(map[string]*callInfo)
	for _, callId := range mainOpts.Args.CallIds {
		callIds[callId] = &callInfo{
			rtpIPs: make(map[string]bool),
		}
	}

	callIdsPending := len(callIds)

	rtpDstPorts := make(map[int]string)

	// regexp to get the ports from m=audio header
	mediaRegExp := regexp.MustCompile(`m=audio (\d+)(?:/(\d+))? RTP/AVP`)
	// regexp to get IP addresses from c= connection line
	connectionRegExp := regexp.MustCompile(`c=IN IP[46] ([\da-fA-F:.]+)`)

	// pcap out handling
	var pcapOutH *os.File = os.Stdout
	if mainOpts.PcapOut != "" {
		pcapOutH, err = os.Create(mainOpts.PcapOut)
		if err != nil {
			panic(err)
		}
	}
	defer pcapOutH.Close()
	var pcapOutWriter *pcapgo.Writer

	// pcap in handling
	var pcapInH *os.File = os.Stdin
	if mainOpts.PcapIn != "" {
		pcapInH, err = os.Open(mainOpts.PcapIn)
		if err != nil {
			panic(err)
		}
	}
	defer pcapInH.Close()

	pcapInReader, err := pcapgo.NewReader(pcapInH)
	if err != nil {
		panic(err)
	}

	decodeOptions := gopacket.DecodeOptions{Lazy: true, NoCopy: true}

	for {
		var decodeAs packetType = 0

		data, ci, err := pcapInReader.ReadPacketData()

		if data == nil {
			break
		}
		if err != nil {
			panic(err)
		}

		// Need at least Ethernet header
		if len(data) < 14 {
			continue
		}

		var (
			packet     gopacket.Packet
			udpSrcPort int
			udpDstPort int
		)

		isIPv4 := bytes.Equal(data[12:14], []byte{8, 0})       // 0x0800
		isIPv6 := bytes.Equal(data[12:14], []byte{0x86, 0xdd}) // 0x86DD

		if isIPv4 {
			if len(data) < 42 { // min length of Ethernet + IPv4 + UDP headers
				continue
			}
			if data[23] != 17 { // IPv4 protocol
				// not UDP
				continue
			}
			udpSrcPort = int(data[34])<<8 + int(data[35])
			udpDstPort = int(data[36])<<8 + int(data[37])
		} else if isIPv6 {
			if len(data) < 62 { // min length of Ethernet + IPv6 + UDP headers
				continue
			}
			// For IPv6, use gopacket to find UDP ports (handles extension headers)
			packet = gopacket.NewPacket(data, pcapInReader.LinkType(), decodeOptions)
			udp, ok := packet.TransportLayer().(*layers.UDP)
			if !ok {
				continue
			}
			udpSrcPort = int(udp.SrcPort)
			udpDstPort = int(udp.DstPort)
		} else {
			// not IPv4/IPv6
			continue
		}

		if _, exists := sipPorts[udpDstPort]; exists {
			decodeAs = packetSIP
		} else if _, exists := sipPorts[udpSrcPort]; exists {
			decodeAs = packetSIP
		} else if _, exists := rtpDstPorts[udpDstPort]; exists && !mainOpts.SkipRtp {
			decodeAs = packetRTP
		}

		if decodeAs == 0 {
			continue
		}

		if pcapOutWriter == nil {
			pcapOutWriter = pcapgo.NewWriter(pcapOutH)
			pcapOutWriter.WriteFileHeader(65536, layers.LinkTypeEthernet)
		}

		if packet == nil {
			packet = gopacket.NewPacket(data, pcapInReader.LinkType(), decodeOptions)
		}
		m := packet.Metadata()
		m.CaptureInfo = ci
		m.Truncated = m.Truncated || ci.CaptureLength < ci.Length

		if decodeAs == packetRTP {
			callId := rtpDstPorts[udpDstPort]
			call := callIds[callId]

			if call.finished.IsZero() || call.finished.Add(time.Duration(mainOpts.RtpTail)*time.Second).After(m.Timestamp) {
				if mainOpts.RtpFilterIP {
					switch ip := packet.NetworkLayer().(type) {
					case *layers.IPv4:
						if !call.rtpIPs[ip.SrcIP.String()] && !call.rtpIPs[ip.DstIP.String()] {
							continue
						}
					case *layers.IPv6:
						if !call.rtpIPs[ip.SrcIP.String()] && !call.rtpIPs[ip.DstIP.String()] {
							continue
						}
					default:
						continue
					}
				}
				pcapOutWriter.WritePacket(ci, data)
			}

		} else if decodeAs == packetSIP {
			var srcIPStr, dstIPStr string
			switch ip := packet.NetworkLayer().(type) {
			case *layers.IPv4:
				srcIPStr, dstIPStr = ip.SrcIP.String(), ip.DstIP.String()
			case *layers.IPv6:
				srcIPStr, dstIPStr = ip.SrcIP.String(), ip.DstIP.String()
			default:
				continue
			}

			if sip, ok := packet.ApplicationLayer().(*layers.SIP); ok {
				if call, exists := callIds[sip.GetCallID()]; exists {

					call.packets++
					call.last = m.Timestamp
					call.lastSipPacket = sip

					if call.started.IsZero() {
						call.started = m.Timestamp

						// this is the first SIP packet which should be an INVITE
						if sip.Method == layers.SIPMethodInvite && !sip.IsResponse {
							call.startedWithInvite = true
						}
					}

					// ACK after final non-2xx responses (e.g. 487 after CANCEL)
					if sip.Method == layers.SIPMethodAck && !sip.IsResponse && call.ackPending && !call.doneCounted {
						call.ackPending = false
						call.ackSeen = true
						call.doneCounted = true
						callIdsPending--
					}

					// Mark call finished on BYE response OR final non-2xx responses (3xx-6xx).
					// For non-2xx, don't consider the call "done" until we saw the final ACK.
					if sip.IsResponse {
						isBye := sip.Method == layers.SIPMethodBye
						isFinalNonSuccess := sip.ResponseCode >= 300 && sip.ResponseCode < 700

						if isBye {
							if !call.doneCounted {
								call.doneCounted = true
								callIdsPending--
							}
							call.finished = m.Timestamp
						} else if isFinalNonSuccess {
							call.finished = m.Timestamp
							if !call.ackSeen {
								call.ackPending = true
							}
						}
					}

					methodOrResponse := "> " + sip.Method.String()
					if sip.IsResponse {
						methodOrResponse = "< " + strconv.Itoa(sip.ResponseCode) + " " + sip.ResponseStatus
					}
					verboseOut(1, "%s: [%s] %s -- from %s:%d to %s:%d\n", sip.GetCallID(), m.Timestamp.Local().Format(time.RFC3339), methodOrResponse, srcIPStr, udpSrcPort, dstIPStr, udpDstPort)
					sipRaw := append(sip.LayerContents(), sip.Payload()...)
					verboseOut(2, "%s\n\n", bytes.TrimRight(sipRaw, "\r\n"))

					if sip.GetFirstHeader("content-type") == "application/sdp" {
						sdpPayload := string(sip.Payload())

						res := mediaRegExp.FindStringSubmatch(sdpPayload)
						if len(res) != 3 {
							continue
						}

						if res[2] == "" {
							res[2] = "1"
						}

						rtpPort, err := strconv.Atoi(res[1])
						if err != nil {
							continue
						}

						call.rtpPairs, err = strconv.Atoi(res[2])
						if err != nil {
							continue
						}

						for port := rtpPort; port < rtpPort+call.rtpPairs*2; port++ {
							rtpDstPorts[port] = sip.GetCallID()
						}

						// Extract IPs from c= connection lines
						if mainOpts.RtpFilterIP {
							for _, match := range connectionRegExp.FindAllStringSubmatch(sdpPayload, -1) {
								if len(match) >= 2 {
									if ip := net.ParseIP(match[1]); ip != nil {
										call.rtpIPs[match[1]] = true
									}
								}
							}
						}
					}

					pcapOutWriter.WritePacket(ci, data)
				}

			}
		}

		if callIdsPending == 0 && !mainOpts.FullScan {
			break
		}
	}

	for callId, callInfo := range callIds {
		if callInfo.last.IsZero() {
			verboseOut(0, "%s: no packets found for this call\n", callId)
		} else if !callInfo.startedWithInvite {
			verboseOut(0, "%s: did not start with INVITE\n", callId)
		}
	}
}

func verboseOut(level int, format string, a ...any) {
	if level > verbosity {
		return
	}
	fmt.Fprintf(os.Stderr, format, a...)
}
