package reverseguard

import (
	"fmt"
	"os"
	"time"
)

var logChan chan string
var errChan chan string

func writeOut(msg string) {
	if logChan != nil {
		logChan <- fmt.Sprintf("time=%q level=info msg=%q", time.Now().Format("2006-01-02T15:04:05Z"), msg) + "\n"
		return
	}

	logChan = make(chan string)

	// logging routine
	go func() {
		for {
			select {
			case msg := <-logChan:
				_, _ = os.Stdout.WriteString(msg)
			default:
				time.Sleep(1 * time.Second)
			}
		}
	}()

	writeOut(msg)
}

func writeErr(msg string) {
	if errChan != nil {
		errChan <- msg + "\n"
		return
	}

	errChan = make(chan string)

	// logging routine
	go func() {
		for {
			select {
			case msg := <-errChan:
				_, _ = os.Stderr.WriteString(msg)
			default:
				time.Sleep(1 * time.Second)
			}
		}
	}()

	writeErr(msg)
}
