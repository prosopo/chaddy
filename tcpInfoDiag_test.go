package caddy_clienthello

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestQueryTcpInfoFindsARealSocket(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "[::1]"} {
		t.Run(host, func(t *testing.T) {
			listener, err := net.Listen("tcp", host+":0")
			if err != nil {
				t.Skip(err)
			}
			defer listener.Close()
			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			if _, err := client.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			if _, err := server.Read(make([]byte, 5)); err != nil {
				t.Fatal(err)
			}

			raw, err := queryTcpInfo(server.LocalAddr().(*net.TCPAddr), server.RemoteAddr().(*net.TCPAddr))
			if err != nil {
				t.Fatal(err)
			}
			info := renderTcpInfo(raw)
			if info["state"] != 1 || info["bytes_received"] != 5 {
				t.Fatalf("wrong socket or layout: %v", info)
			}
		})
	}
}

func TestQueryTcpInfoReportsAMissingSocket(t *testing.T) {
	gone := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}
	if _, err := queryTcpInfo(gone, gone); err == nil {
		t.Fatal("expected an error")
	}
}

func TestWithTcpInfo(t *testing.T) {
	hit := []byte(`{"hit":true,"pkts":[1],"local_ip":"10.0.0.2","local_port":443,"remote_ip":"2001:db8::1","remote_port":5}`)
	raw := make([]byte, tcpInfoSize)
	raw[0] = 1
	found := func(local, remote *net.TCPAddr) ([]byte, error) {
		if fmt.Sprint(local, remote) != "10.0.0.2:443 [2001:db8::1]:5" {
			t.Fatalf("queried %v %v", local, remote)
		}
		return raw, nil
	}
	merged, err := withTcpInfo(hit, found)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Pkts    []int             `json:"pkts"`
		TcpInfo map[string]uint64 `json:"tcp_info"`
	}
	if err := json.Unmarshal(merged, &record); err != nil {
		t.Fatal(err)
	}
	if record.TcpInfo["state"] != 1 || len(record.Pkts) != 1 {
		t.Fatalf("got %s", merged)
	}

	failed := func(_, _ *net.TCPAddr) ([]byte, error) { return nil, errors.New("gone") }
	kept, err := withTcpInfo(hit, failed)
	if err == nil || string(kept) != string(hit) {
		t.Fatalf("record not kept on failure: %s, %v", kept, err)
	}

	miss := []byte(`{"hit":false,"reason":"no_record"}`)
	if kept, err := withTcpInfo(miss, failed); err != nil || string(kept) != string(miss) {
		t.Fatalf("miss changed: %s, %v", kept, err)
	}
}
