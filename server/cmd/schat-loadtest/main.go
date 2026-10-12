// Command schat-loadtest opens many WebSocket connections to a relay and holds them open,
// so that the memory cost of a connected client can be measured instead of estimated.
//
// # Why this exists
//
// "How big a server do I need" is answered by one number: bytes of resident memory per
// connected client. Everything else about this relay is trivially small — the binary is
// about 10 MB and an idle process holds about 11 MB — so that single number decides whether
// a €4 instance serves fifty people or five thousand.
//
// It is a measurement tool, not a client: it subscribes to distinct mailboxes so that the
// relay keeps per-connection state (which is what a real client causes and therefore what
// the measurement must include), then sits still.
//
// Usage:
//
//	go run ./cmd/schat-loadtest -url ws://127.0.0.1:8443/ws -n 1000 -hold 20s
//
// See tools/measure-relay-load.ps1, which drives this and records the server's working set.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/schat/schat/server/internal/wstest"
)

func main() {
	url := flag.String("url", "ws://127.0.0.1:8443/ws", "relay WebSocket URL")
	count := flag.Int("n", 100, "number of connections to open and hold")
	hold := flag.Duration("hold", 20*time.Second, "how long to hold them open")
	subscribe := flag.Bool("subscribe", true, "subscribe each connection to its own mailbox")
	flag.Parse()

	if *count <= 0 {
		log.Fatal("n must be positive")
	}

	conns := make([]*wstest.Client, 0, *count)

	started := time.Now()
	for i := 0; i < *count; i++ {
		client, err := wstest.Dial(*url)
		if err != nil {
			log.Fatalf("connection %d of %d: %v", i, *count, err)
		}

		if *subscribe {
			// A distinct, well-formed 16-byte token per connection, so the relay's router
			// and directory hold realistic per-client state.
			token := fmt.Sprintf("%032x", i+1)
			command := fmt.Sprintf(`{"t":"sub","tokens":["%s"]}`, token)
			if err := client.WriteText([]byte(command)); err != nil {
				log.Fatalf("subscribe %d: %v", i, err)
			}
		}
		conns = append(conns, client)
	}
	log.Printf("opened %d connections in %s; holding for %s", len(conns), time.Since(started).Round(time.Millisecond), *hold)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	select {
	case <-signals:
	case <-time.After(*hold):
	}

	for _, client := range conns {
		_ = client.Close()
	}
	log.Printf("closed %d connections", len(conns))
}
