package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ifandonlyif-io/iff-witness-example"
)

func main() {
	config, err := witness.ConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	app, err := witness.NewServer(config)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: app.ListenAddr(), Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 85 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("IFF Witness is listening on %s (rehearsal is the default)", app.ListenAddr())
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
