package ulog

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/stat"
	"gopkg.in/natefinch/lumberjack.v2"
)

var Log *Logger = New(context.Background())

const (
	logDir      = "/var/log"
	logFileBase = "xray-conn"
	maxSize     = 1024 // 1 GB
	maxAge      = 3    // 3 days
	maxBackups  = 5
)

var (
	logFile = logFileBase + ".log"
	curFile = filepath.Join(logDir, logFile)
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

	log       *log.Logger
	startTime time.Time
}

func New(ctx context.Context) *Logger {
	ctx, cancel := context.WithCancel(ctx)

	l := &Logger{
		ctx:       ctx,
		cancel:    cancel,
		log:       log.New(newLumberjackLogger(), "", 0),
		startTime: getStartTime(),
	}
	l.runRotationLoop()
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
		l.log.Printf("T=%s S=%s SP=%d D=%s DP=%d N=%s P=%s U=%s",
			ts.Format("01-02:15:04:05"), params.SrcIP, params.SrcPort, params.DstIP,
			params.DstPort, params.DstName, params.Protocol, params.UUID)
	} else {
		l.log.Printf("T=%s S=%s SP=%d D=%s DP=%d P=%s U=%s",
			ts.Format("01-02:15:04:05"), params.SrcIP, params.SrcPort, params.DstIP,
			params.DstPort, params.Protocol, params.UUID)
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
	if inbound != nil {
		if inbound.User != nil {
			params.UUID = inbound.User.Email
		}

		if inbound.Source.IsValid() {
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
	}

	l.LogConnectionRaw(time.Now(), params)
}

func (l *Logger) runRotationLoop() {
	go func() {
		for {
			select {
			case <-l.ctx.Done():
				return
			case <-time.After(time.Minute):
				time.Sleep(l.calcRotationSleepTime())
				l.rotate()
			}
		}
	}()
}

func (l *Logger) calcRotationSleepTime() time.Duration {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return 24*time.Hour - time.Since(l.startTime)
}

func (l *Logger) rotate() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.startTime = time.Now()
	l.log.Writer().(*lumberjack.Logger).Close()

	// Remove oldest file
	os.Remove(filepath.Join(logDir, fmt.Sprintf("%s.%d.gz", logFileBase, maxAge-1)))

	// Rename files
	for i := maxAge - 2; i > 0; i-- {
		src := filepath.Join(logDir, fmt.Sprintf("%s.%d.gz", logFileBase, i))
		dst := filepath.Join(logDir, fmt.Sprintf("%s.%d.gz", logFileBase, i+1))
		os.Rename(src, dst)
	}

	// Compress current file
	if _, err := os.Stat(curFile); err == nil {
		cmd := exec.Command("gzip", "-c", curFile)
		out, err := os.Create(filepath.Join(logDir, fmt.Sprintf("%s.1.gz", logFileBase)))
		if err != nil {
			os.Rename(curFile, filepath.Join(logDir, fmt.Sprintf("%s.1.log", logFileBase)))
		} else {
			cmd.Stdout = out
			cmd.Run()
			out.Close()
			os.Remove(curFile)
		}
	}

	l.log.SetOutput(newLumberjackLogger())
	logrus.Debug("[wgi-conn] Rotated log file")
}

type ConnectionParams struct {
	SrcIP    string
	SrcPort  uint16
	DstIP    string
	DstPort  uint16
	DstName  string
	Protocol string
	UUID     string
}

func newLumberjackLogger() *lumberjack.Logger {
	return &lumberjack.Logger{
		Filename:   curFile,
		MaxSize:    maxSize,
		MaxAge:     maxAge,
		MaxBackups: maxBackups,
		Compress:   true,
	}
}

func getStartTime() time.Time {
	file, err := os.Open(curFile)
	if err != nil {
		return time.Now()
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		if t := parseLogTime(scanner.Text()); t != nil {
			return *t
		}
	}

	return time.Now()
}

func parseLogTime(line string) *time.Time {
	for _, part := range strings.Split(line, " ") {
		if strings.HasPrefix(part, "T=") {
			t, err := time.Parse("01-02:15:04:05", part[2:])
			if err != nil {
				return nil
			}
			now := time.Now()
			t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(),
				t.Minute(), t.Second(), 0, time.Local)
			return &t
		}
	}

	return nil
}
