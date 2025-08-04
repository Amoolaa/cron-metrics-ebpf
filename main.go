package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	taskCommLen       = 16
	cmdLineMax        = 128
	maxEntriesRingbuf = 10240
	maxEntriesRunning = 10240
	maxEntriesCount   = 10240
)

type cronEvent struct {
	PID       uint32
	PPID      uint32
	StartTime uint64
	Duration  uint64
	ExitCode  int32
	Comm      [taskCommLen]byte
	CmdLine   [cmdLineMax]byte
}

var wg sync.WaitGroup

var (
	cronJobCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cron_job_executions_total",
			Help: "Total number of cron job executions",
		},
		[]string{"comm", "command_line"},
	)

	cronJobDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cron_job_duration_seconds",
			Help:    "Duration of cron job executions in seconds",
			Buckets: prometheus.ExponentialBuckets(0.1, 2.0, 10),
		},
		[]string{"comm", "command_line"},
	)

	cronJobExitCodes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cron_job_exit_codes_total",
			Help: "Exit codes of cron jobs",
		},
		[]string{"comm", "command_line", "exit_code"},
	)
)

func init() {
	prometheus.MustRegister(cronJobCount)
	prometheus.MustRegister(cronJobDuration)
	prometheus.MustRegister(cronJobExitCodes)
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -type cron_event -target bpf bpf cron_metrics.c -- -I/usr/include/x86_64-linux-gnu -D__TARGET_ARCH_$GOARCH -O2 -g

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	// allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("error removing memlock", "error", err)
		os.Exit(1)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		slog.Error("error loading objects", "error", err)
		os.Exit(1)
	}
	defer objs.Close()

	execTp, err := link.Tracepoint("sched", "sched_process_exec", objs.TraceExec, nil)
	if err != nil {
		slog.Error("error attaching sched_process_exec tracepoint", "error", err)
		os.Exit(1)
	}
	defer execTp.Close()

	exitTp, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceExit, nil)
	if err != nil {
		slog.Error("error while attaching sched_process_exit tracepoint", "error", err)
		os.Exit(1)
	}
	defer exitTp.Close()

	rd, err := perf.NewReader(objs.CronEvents, os.Getpagesize()*32)
	if err != nil {
		slog.Error("error while creating perf event reader", "error", err)
		os.Exit(1)
	}
	defer rd.Close()

	wg.Add(2)

	// channel to signal shutdown
	stop := make(chan struct{})

	// process events from perf buffer
	events := make(chan cronEvent)
	go processEvents(rd, events, stop, &wg)
	go handleEvents(&wg, events)

	srv := &http.Server{Addr: ":2112"}
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("error starting server", "error", err)
		}
	}()

	slog.Info("serving metrics on localhost:2112/metrics")

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	sig := <-c
	slog.Info("received signal, shutting down", "signal", sig)
	close(stop)
	rd.Close()
	wg.Wait()
	if err := srv.Close(); err != nil {
		slog.Error("error closing server", "error", err)
		os.Exit(1)
	}
}

func processEvents(rd *perf.Reader, events chan<- cronEvent, stop <-chan struct{}, wg *sync.WaitGroup) {
	var event cronEvent
	defer func() {
		close(events)
		wg.Done()
	}()

	for {
		select {
		case <-stop:
			return
		default:
			record, err := rd.Read()
			if err != nil {
				if err == perf.ErrClosed {
					slog.Error("perf buffer is closed, returning")
					return
				}
				if perf.IsUnknownEvent(err) {
					slog.Error("unknown event", "event", err)
					continue
				}
				slog.Error("error reading from perf buffer", "error", err)
				continue
			}

			if len(record.RawSample) < binary.Size(&event) {
				slog.Error("record too short", "error", fmt.Sprintf("%d < %d", len(record.RawSample), binary.Size(&event)))
				continue
			}
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				slog.Error("error parsing event", "error", err)
				continue
			}
		}

		select {
		case events <- event:
		case <-stop:
			return
		}
	}
}

func handleEvents(wg *sync.WaitGroup, events <-chan cronEvent) {
	defer wg.Done()

	for event := range events {
		// convert command name from fixed-size array to string
		comm := strings.TrimRight(string(event.Comm[:]), "\x00")
		cmdLine := strings.TrimRight(string(event.CmdLine[:]), "\x00")

		cronJobCount.WithLabelValues(comm, cmdLine).Inc()
		cronJobDuration.WithLabelValues(comm, cmdLine).Observe(float64(event.Duration) / 1e9)
		cronJobExitCodes.WithLabelValues(comm, cmdLine, fmt.Sprintf("%d", event.ExitCode)).Inc()

		slog.Info("cron job completed", "comm", comm, "command_line", cmdLine, "pid", event.PID, "ppid", event.PPID, "duration", float64(event.Duration)/1e9, "exit_code", event.ExitCode)
	}
}
