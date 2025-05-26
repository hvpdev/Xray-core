package bittorrent

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/log"
)

type void struct{}

const ipUpdateInterval = 30 * time.Minute

var (
	hostWhitelist = []string{
		"instagram.com",
		"youtube.com",
		"www.youtube.com",
	}
)

type BittorrentAnalyzer struct {
	mu      sync.RWMutex
	ctx     context.Context
	wlHost  map[string]void
	wlIP    map[string]void
	matcher *ruleMatcher
}

func NewBittorrentAnalyzer(
	ctx context.Context,
	rulesFiles []string,
	whitelist []string,
) (*BittorrentAnalyzer, error) {
	wlHost := make(map[string]void, len(whitelist)+len(hostWhitelist))
	for _, host := range whitelist {
		wlHost[host] = void{}
	}
	for _, host := range hostWhitelist {
		wlHost[host] = void{}
	}

	rules, err := parseRulesFromFiles(rulesFiles)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rules: %w", err)
	}

	matcher, err := newRuleMatcher(rules)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule matcher: %w", err)
	}

	ba := &BittorrentAnalyzer{
		ctx:     ctx,
		wlHost:  wlHost,
		wlIP:    make(map[string]void, len(wlHost)),
		matcher: matcher,
	}
	go ba.updateIPsLoop()

	return ba, nil
}

func (ba *BittorrentAnalyzer) updateIPsLoop() {
	ticker := time.NewTicker(ipUpdateInterval)
	defer ticker.Stop()

	ba.updateIPs()

	for {
		select {
		case <-ticker.C:
			ba.updateIPs()
		case <-ba.ctx.Done():
			return
		}
	}
}

func (ba *BittorrentAnalyzer) updateIPs() {
	for host := range ba.wlHost {
		ips, err := net.LookupIP(host)
		if err != nil {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Error,
				Content:  fmt.Sprintf("Failed to lookup IPs for %s: %v", host, err),
			})
			continue
		}

		ba.mu.Lock()
		for _, ip := range ips {
			ba.wlIP[ip.String()] = void{}
		}
		ba.mu.Unlock()
	}
}

func (ba *BittorrentAnalyzer) IsHostWhitelisted(host string) bool {
	_, ok := ba.wlHost[host]
	return ok
}

func (ba *BittorrentAnalyzer) IsIPWhitelisted(ip string) bool {
	ba.mu.RLock()
	_, ok := ba.wlIP[ip]
	ba.mu.RUnlock()
	return ok
}

func (ba *BittorrentAnalyzer) Match(data []byte) (bool, string) {
	rule := ba.matcher.match(data)
	if rule == nil {
		return false, ""
	}
	return true, rule.rule.String()
}

func FindRulesFiles(dir string) ([]string, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}

	var rulesFiles []string
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Check if file has .rules extension
		if strings.HasSuffix(file.Name(), ".rules") {
			rulesFiles = append(rulesFiles, file.Name())
		}
	}

	return rulesFiles, nil
}
