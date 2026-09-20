// Command sipsend sends one INVITE over UDP and prints the first response
// status code. It exists so the Kamailio adapter test needs no sipp.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	target := flag.String("to", "127.0.0.1:5060", "SIP UDP address")
	from := flag.String("from", "+13125550188", "calling number")
	callee := flag.String("callee", "+14155550100", "called number")
	ua := flag.String("ua", "sipsend/1.0", "User-Agent")
	flag.Parse()

	conn, err := net.DialTimeout("udp", *target, 3*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer conn.Close()
	local := conn.LocalAddr().String()
	callID := fmt.Sprintf("sipsend-%d@%s", time.Now().UnixNano(), strings.Split(local, ":")[0])
	msg := strings.Join([]string{
		fmt.Sprintf("INVITE sip:%s@%s SIP/2.0", *callee, *target),
		fmt.Sprintf("Via: SIP/2.0/UDP %s;branch=z9hG4bK%d;rport", local, time.Now().UnixNano()),
		"Max-Forwards: 70",
		fmt.Sprintf("From: <sip:%s@%s>;tag=%d", *from, local, time.Now().Unix()),
		fmt.Sprintf("To: <sip:%s@%s>", *callee, *target),
		"Call-ID: " + callID,
		"CSeq: 1 INVITE",
		fmt.Sprintf("Contact: <sip:%s@%s>", *from, local),
		"User-Agent: " + *ua,
		"Content-Length: 0",
		"", "",
	}, "\r\n")
	if _, err := conn.Write([]byte(msg)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	final := ""
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		final = f[1]
		if !strings.HasPrefix(final, "1") {
			break
		}
	}
	if final == "" {
		fmt.Fprintln(os.Stderr, "no response")
		os.Exit(3)
	}
	fmt.Println(final)
}
