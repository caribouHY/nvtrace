package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	NUMBER = iota
	LOCAL
	REMOTE
	COOKIES
	EXCHANGE
	DATA
)

var (
	num_reg = regexp.MustCompile(`^\[\d\d?\]$`)
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: vntrace filename")
		return
	}

	input_path := os.Args[1]
	//output_path := input_path + ".pcap"

	fp, err := os.Open(input_path)
	if err != nil {
		return
	}
	defer fp.Close()

	scanner := bufio.NewScanner(fp)
	state := NUMBER
	var data []byte
	data_len := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}

		switch state {
		case NUMBER:
			num, send, time, err := parseNumber(line)
			if err == nil {
				fmt.Printf("num = %d, send=%t, time=%s\n", num, send, time)
				state++
			}
		case LOCAL:
			ip := parseAddress(line, true)
			fmt.Println(" local =", ip)
			state++
		case REMOTE:
			ip := parseAddress(line, false)
			fmt.Println(" remote =", ip)
			state++
		case COOKIES:
			res := isCookies(line)
			if res {
				state++
			} else {
				fmt.Println("format error")
				return
			}
		case EXCHANGE:
			data_len = parseLen(line)
			if data_len == 0 {
				fmt.Println("excahge type format error")
				return
			} else {
				fmt.Println(" len =", data_len)
				data = make([]byte, 0, data_len)
				state++
			}
		case DATA:
			res := parseData(line, len(data) == 0)
			if res == nil {
				fmt.Println("data format error")
				return
			}
			data = append(data, res...)
			if len(data) > data_len {
				fmt.Println("data size format error")
				return
			}
			if data_len == len(data) {
				fmt.Println(data)
				state = NUMBER
			}
		}
	}

	fmt.Print("Press Enter to exit. >")
	bufio.NewScanner(os.Stdin).Scan()
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

func parseAddress(line string, local bool) *net.IP {
	prefix := "Remote Address:("
	if local {
		prefix = "Local  Address:("
	}
	if !(strings.HasPrefix(line, prefix) && line[len(line)-1] == ')') {
		return nil
	}
	s := line[len(prefix) : len(line)-1]
	ip := net.ParseIP(s)
	return &ip
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
