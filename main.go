package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type IsakmpTrace struct {
	Timestamp     *time.Time
	IsSend        bool
	LocalAddress  net.IP
	RemoteAddress net.IP
	Data          []byte
}

const (
	NUMBER = iota
	LOCAL
	REMOTE
	COOKIES
	EXCHANGE
	DATA
)

var (
	local_mac  net.HardwareAddr
	remote_mac net.HardwareAddr
)

var (
	num_reg = regexp.MustCompile(`^\[\d\d?\]$`)
)

func main() {
	var (
		debug       = flag.Bool("d", false, "debug message")
		output      = flag.String("o", "", "output pcap file")
		wait        = false
		output_path string
	)
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Printf("Missing filename.")
		os.Exit(1)
	}
	input_path := flag.Arg(0)
	if *output == "" {
		wait = true
		output_path = input_path + ".pcap"
	} else {
		output_path = *output
	}
	if *debug {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(io.Discard)
	}
	log.SetFlags(0)

	packet_arry, err := readTrace(input_path)
	if err != nil {
		fmt.Println("import failed!")
		fmt.Println(err)
		os.Exit(1)
	}

	//log.Println(packet_arry)
	local_mac, _ = net.ParseMAC("00:00:5e:00:53:01")
	remote_mac, _ = net.ParseMAC("00:00:5e:00:53:02")
	err = savePcap(output_path, packet_arry)
	if err != nil {
		fmt.Println("export failed!")
		fmt.Println(err)
		os.Exit(1)
	}

	if wait {
		fmt.Println("exported to", output_path)
		fmt.Print("Press Enter to exit. >")
		bufio.NewScanner(os.Stdin).Scan()
	}
}

func readTrace(filepath string) ([]IsakmpTrace, error) {
	fp, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	scanner := bufio.NewScanner(fp)

	state := NUMBER
	var data []byte
	data_len := 0
	packet_arry := make([]IsakmpTrace, 0, 30)
	var packet IsakmpTrace
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}

		switch state {
		case NUMBER:
			num, send, time, err := parseNumber(line)
			if err == nil {
				log.Printf("num = %d, send=%t, time=%s\n", num, send, time)
				packet = IsakmpTrace{Timestamp: time, IsSend: send}
				state++
			}
		case LOCAL:
			ip := parseAddress(line, true)
			if ip == nil {
				return nil, fmt.Errorf("format error: local address is invailed")
			}
			log.Println("local =", ip)
			packet.LocalAddress = ip
			state++
		case REMOTE:
			ip := parseAddress(line, false)
			if ip == nil {
				return nil, fmt.Errorf("format error: remote address is invailed")
			}
			log.Println("remote =", ip)
			packet.RemoteAddress = ip
			state++
		case COOKIES:
			res := isCookies(line)
			if res {
				state++
			} else {
				return nil, fmt.Errorf("format error: cookie is invailed")
			}
		case EXCHANGE:
			data_len = parseLen(line)
			if data_len == 0 {
				fmt.Println("excahge type format error")
				return nil, fmt.Errorf("format error: exhange is invailed")
			} else {
				log.Println("len =", data_len)
				data = make([]byte, 0, data_len)
				state++
			}
		case DATA:
			res := parseData(line, len(data) == 0)
			if res == nil {
				return nil, fmt.Errorf("format error: data is invailed")
			}
			data = append(data, res...)
			if len(data) > data_len {
				return nil, fmt.Errorf("format error: data is longer than Len:%d", data_len)
			}
			if data_len == len(data) {
				log.Println("data =", data)
				state = NUMBER
				packet.Data = data
				packet_arry = append(packet_arry, packet)
			}
		}
	}
	return packet_arry, nil
}

func parseNumber(line string) (int, bool, *time.Time, error) {
	line_arr := strings.Fields(line)
	size := len(line_arr)
	format_err := fmt.Errorf("format error")

	if size != 7 && size != 8 {
		return 0, false, nil, format_err
	}
	if line_arr[1] != "ISAKMP" {
		return 0, false, nil, format_err
	}
	// number
	if !num_reg.MatchString(line_arr[0]) {
		return 0, false, nil, format_err
	}
	num, err := strconv.Atoi(line_arr[0][1 : len(line_arr[0])-1])
	if err != nil {
		return 0, false, nil, format_err
	}
	// send or recieve
	var send bool
	if strings.HasPrefix(line_arr[2], "Send") {
		send = true
	} else if strings.HasPrefix(line_arr[2], "Receive") {
		send = false
	} else {
		return 0, false, nil, format_err
	}
	// time
	time, err := time.Parse("2 Jan 2006 15:04:05", strings.Join([]string{line_arr[size-3], line_arr[size-4], line_arr[size-1], line_arr[size-2]}, " "))
	if err != nil {
		return 0, false, nil, format_err
	}
	return num, send, &time, nil
}

func parseAddress(line string, local bool) net.IP {
	prefix := "Remote Address:("
	if local {
		prefix = "Local  Address:("
	}
	if !(strings.HasPrefix(line, prefix) && line[len(line)-1] == ')') {
		return nil
	}
	s := line[len(prefix) : len(line)-1]
	ip := net.ParseIP(s)
	return ip
}

func isCookies(line string) bool {
	return strings.HasPrefix(line, "Cookies:(") && len(line) == 43
}

func parseLen(line string) int {
	if !strings.HasPrefix(line, "Exchange Type: ") {
		return 0
	}
	p1 := strings.LastIndex(line, ":")
	p2 := strings.LastIndex(line, "(")
	if p2 == -1 || p1 > p2 {
		return 0
	}
	length, err := strconv.Atoi(line[p1+1 : p2])
	if err != nil {
		return 0
	}
	return length
}

func parseData(line string, head bool) []byte {
	var line_arr []string
	if head {
		if !strings.HasPrefix(line, "data=") {
			return nil
		}
		line_arr = strings.Fields(line[5:])
	} else {
		line_arr = strings.Fields(line)
	}
	data := make([]byte, 0, 16)
	size := 0
	for _, v := range line_arr {
		l := len(v)
		if l == 2 {
			d, e := strconv.ParseUint(v, 16, 8)
			if e != nil {
				return nil
			}
			data = append(data, byte(d))
			size++
		} else if l == 4 {
			d1, e := strconv.ParseUint(v[:2], 16, 8)
			if e != nil {
				return nil
			}
			d2, e := strconv.ParseUint(v[2:], 16, 8)
			if e != nil {
				return nil
			}
			data = append(data, byte(d1), byte(d2))
			size += 2
		} else {
			return nil
		}
	}
	return data
}

func savePcap(filepath string, trace_data []IsakmpTrace) error {
	fp, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer fp.Close()

	wr := pcapgo.NewWriter(fp)
	wr.WriteFileHeader(65535, layers.LinkTypeEthernet)

	for _, v := range trace_data {
		ci, buf, err := serializeTrace(&v)
		if err != nil {
			return err
		}
		wr.WritePacket(*ci, buf.Bytes())
	}

	return nil
}

func serializeTrace(trace *IsakmpTrace) (*gopacket.CaptureInfo, gopacket.SerializeBuffer, error) {
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buf := gopacket.NewSerializeBuffer()
	ethernet := &layers.Ethernet{}
	var srcIP net.IP
	var dstIP net.IP
	if trace.IsSend {
		ethernet.SrcMAC = local_mac
		ethernet.DstMAC = remote_mac
		srcIP = trace.LocalAddress
		dstIP = trace.RemoteAddress
	} else {
		ethernet.SrcMAC = remote_mac
		ethernet.DstMAC = local_mac
		srcIP = trace.RemoteAddress
		dstIP = trace.LocalAddress
	}

	udp := &layers.UDP{
		SrcPort: 500,
		DstPort: 500,
	}
	if a, _ := netip.ParseAddr(trace.LocalAddress.String()); a.Is6() {
		ethernet.EthernetType = layers.EthernetTypeIPv6
		ip := &layers.IPv6{
			Version:    6,
			HopLimit:   0xff,
			SrcIP:      srcIP,
			DstIP:      dstIP,
			NextHeader: layers.IPProtocolUDP,
		}
		udp.SetNetworkLayerForChecksum(ip)
		err := gopacket.SerializeLayers(buf, opts, ethernet, ip, udp, gopacket.Payload(trace.Data))
		if err != nil {
			return nil, nil, err
		}
	} else {
		ethernet.EthernetType = layers.EthernetTypeIPv4
		ip := &layers.IPv4{
			Version:  4,
			TTL:      0xff,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    srcIP,
			DstIP:    dstIP,
		}
		udp.SetNetworkLayerForChecksum(ip)
		err := gopacket.SerializeLayers(buf, opts, ethernet, ip, udp, gopacket.Payload(trace.Data))
		if err != nil {
			return nil, nil, err
		}
	}
	ci := &gopacket.CaptureInfo{
		Timestamp:      *trace.Timestamp,
		CaptureLength:  len(buf.Bytes()),
		Length:         len(buf.Bytes()),
		InterfaceIndex: 0,
	}
	return ci, buf, nil
}
