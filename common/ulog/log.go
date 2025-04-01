package ulog

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/stat"
	"gopkg.in/natefinch/lumberjack.v2"
)

var Log *Logger = New(context.Background())

const (
	logDir     = "/var/log"
	maxSize    = 1024 // 1 GB
	maxAge     = 1    // 1 day
	maxBackups = 2
)

func LogConnectionRaw(ts time.Time, params ConnectionParams) {
	Log.LogConnectionRaw(ts, params)
}

func LogConnection(ctx context.Context, dest net.Destination, conn stat.Connection) {
	Log.LogConnection(ctx, dest, conn)
}

type Logger struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.RWMutex
	log    *log.Logger
}

func New(ctx context.Context) *Logger {
	ctx, cancel := context.WithCancel(ctx)

	l := &Logger{
		ctx:    ctx,
		cancel: cancel,
		log:    log.New(newLumberjackLogger(), "", 0),
	}
	l.runDailyRotationLoop()
	return l
}

// Close closes the logger and stops the daily rotation loop.
//
// If you want to use custom logger instead of global variable,
// you must to call this function to stop the daily rotation loop.
func (l *Logger) Close() {
	l.cancel()
}

func (l *Logger) LogConnectionRaw(ts time.Time, params ConnectionParams) {
	l.mu.RLock()
	if params.DstName != "" {
		l.log.Printf("T=%s S=%s SP=%d D=%s DP=%d N=%s P=%s",
			ts.Format("01-02:15:04:05"), params.SrcIP, params.SrcPort, params.DstIP,
			params.DstPort, params.DstName, params.Protocol)
	} else {
		l.log.Printf("T=%s S=%s SP=%d D=%s DP=%d P=%s",
			ts.Format("01-02:15:04:05"), params.SrcIP, params.SrcPort, params.DstIP,
			params.DstPort, params.Protocol)
	}
	l.mu.RUnlock()
}

func (l *Logger) LogConnection(ctx context.Context, dest net.Destination, conn stat.Connection) {
	protocol := dest.Network.String()
	if len(protocol) > 1 {
		protocol = protocol[:1]
	}

	params := ConnectionParams{
		DstPort:  uint16(dest.Port),
		Protocol: protocol,
	}

	if dest.Address.Family().IsDomain() {
		params.DstName = dest.Address.Domain()
		if outbounds := session.OutboundsFromContext(ctx); len(outbounds) > 0 {
			ob := outbounds[len(outbounds)-1]
			if ob.Target.IsValid() && ob.Target.Address.Family().IsIP() {
				params.DstIP = ob.Target.Address.IP().String()
			}
		}

		if params.DstIP == "" && conn != nil {
			if addr := conn.RemoteAddr(); addr != nil {
				switch addr := addr.(type) {
				case *net.TCPAddr:
					params.DstIP = addr.IP.String()
				case *net.UDPAddr:
					params.DstIP = addr.IP.String()
				}
			}
		}
	} else {
		params.DstIP = dest.Address.IP().String()
	}

	inbound := session.InboundFromContext(ctx)
	if inbound != nil && inbound.Source.IsValid() {
		params.SrcIP = inbound.Source.Address.String()
		params.SrcPort = uint16(inbound.Source.Port)
	} else if conn != nil {
		switch addr := conn.RemoteAddr().(type) {
		case *net.TCPAddr:
			params.SrcIP = addr.IP.String()
			params.SrcPort = uint16(addr.Port)
		case *net.UDPAddr:
			params.SrcIP = addr.IP.String()
			params.SrcPort = uint16(addr.Port)
		default:
			params.SrcIP = conn.RemoteAddr().String()
		}
	}

	l.LogConnectionRaw(time.Now(), params)
}

func (l *Logger) calcNewDayDiff() time.Duration {
	now := time.Now()
	tomorrow := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
	return tomorrow.Sub(now)
}

func (l *Logger) runDailyRotationLoop() {
	go func() {
		for {
			select {
			case <-l.ctx.Done():
				return
			case <-time.After(l.calcNewDayDiff()):
				l.rotate()
				time.Sleep(time.Minute)
			}
		}
	}()
}

func (l *Logger) rotate() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.log.SetOutput(newLumberjackLogger())
}

type ConnectionParams struct {
	SrcIP    string
	SrcPort  uint16
	DstIP    string
	DstPort  uint16
	DstName  string
	Protocol string
}

func getLogFilename() string {
	const logFilePattern = "xray-conn-%s.log"
	return fmt.Sprintf(logFilePattern, time.Now().Format("2006-01-02"))
}

func newLumberjackLogger() *lumberjack.Logger {
	return &lumberjack.Logger{
		Filename:   filepath.Join(logDir, getLogFilename()),
		MaxSize:    maxSize,
		MaxAge:     maxAge,
		MaxBackups: maxBackups,
	}
}
