// Command sipsend sends one SIP request over UDP and prints the first final
// response status code. It exists so the proxy and redirect tests need no
// sipp. Exit 3 means no answer.
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
	method := flag.String("method", "INVITE", "request method (INVITE or OPTIONS)")
	wait := flag.Duration("wait", 5*time.Second, "how long to wait for a final response")
	flag.Parse()

	conn, err := net.DialTimeout("udp", *target, 3*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer conn.Close()
	local := conn.LocalAddr().String()
	callID := fmt.Sprintf("sipsend-%d@%s", time.Now().UnixNano(), strings.Split(local, ":")[0])
	m := strings.ToUpper(*method)
	msg := strings.Join([]string{
		fmt.Sprintf("%s sip:%s@%s SIP/2.0", m, *callee, *target),
		fmt.Sprintf("Via: SIP/2.0/UDP %s;branch=z9hG4bK%d;rport", local, time.Now().UnixNano()),
		"Max-Forwards: 70",
		fmt.Sprintf("From: <sip:%s@%s>;tag=%d", *from, local, time.Now().Unix()),
		fmt.Sprintf("To: <sip:%s@%s>", *callee, *target),
		"Call-ID: " + callID,
		fmt.Sprintf("CSeq: 1 %s", m),
		fmt.Sprintf("Contact: <sip:%s@%s>", *from, local),
		"User-Agent: " + *ua,
		"Content-Length: 0",
		"", "",
	}, "\r\n")
	if _, err := conn.Write([]byte(msg)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	_ = conn.SetReadDeadline(time.Now().Add(*wait))
	buf := make([]byte, 8192)
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
