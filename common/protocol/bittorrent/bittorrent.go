package bittorrent

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
)

const (
	tcpRulesFile = "/usr/local/etc/xray/p2p-tcp.rules"
	udpRulesFile = "/usr/local/etc/xray/p2p-udp.rules"
)

var (
	tcpAnalyzer *BittorrentAnalyzer
	udpAnalyzer *BittorrentAnalyzer
)

func newAnalyzer(isUDP bool) {
	rulesFiles := []string{tcpRulesFile}
	if isUDP {
		rulesFiles = []string{udpRulesFile}
	}
	analyzer, err := NewBittorrentAnalyzer(
		context.Background(),
		rulesFiles,
		[]string{},
	)
	if err != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Error,
			Content:  fmt.Sprintf("Failed to initialize bittorrent analyzer: %v", err),
		})
		os.Exit(1)
	}
	if isUDP {
		udpAnalyzer = analyzer
	} else {
		tcpAnalyzer = analyzer
	}
}

func init() {
	newAnalyzer(false)
	newAnalyzer(true)
}

func getStatManager(ctx context.Context) stats.Manager {
	v := core.MustFromContext(ctx)
	return v.GetFeature(stats.ManagerType()).(stats.Manager)
}

func incStat(ctx context.Context, uuid string) {
	if uuid == "" {
		return
	}
	statsManager := getStatManager(ctx)
	name := fmt.Sprintf("user>>>%s>>>traffic>>>torrent", uuid)
	c, _ := stats.GetOrRegisterCounter(statsManager, name)
	c.Add(1)
}

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "bittorrent"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotBittorrent = errors.New("not bittorrent header")

func SniffBittorrent(ctx context.Context, b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	var uuid string
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		if tcpAnalyzer.IsIPWhitelisted(inbound.Source.NetAddr()) ||
			tcpAnalyzer.IsIPWhitelisted(inbound.Gateway.NetAddr()) {
			return nil, errNotBittorrent
		}
		uuid = inbound.User.Email
	}

	ok, rule := tcpAnalyzer.Match(b)
	if ok {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Debug,
			Content:  fmt.Sprintf("Bittorrent: matched rule: %s", rule),
		})
		incStat(ctx, uuid)
		return &SniffHeader{}, nil
	}

	if b[0] == 19 && string(b[1:20]) == "BitTorrent protocol" {
		incStat(ctx, uuid)
		return &SniffHeader{}, nil
	}

	return nil, errNotBittorrent
}

func SniffUTP(ctx context.Context, b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	var uuid string
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		if udpAnalyzer.IsIPWhitelisted(inbound.Source.NetAddr()) ||
			udpAnalyzer.IsIPWhitelisted(inbound.Gateway.NetAddr()) {
			return nil, errNotBittorrent
		}
		uuid = inbound.User.Email
	}

	ok, rule := udpAnalyzer.Match(b)
	if ok {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Debug,
			Content:  fmt.Sprintf("UTP: matched rule: %s", rule),
		})
		incStat(ctx, uuid)
		return &SniffHeader{}, nil
	}

	buffer := buf.FromBytes(b)

	var typeAndVersion uint8

	if binary.Read(buffer, binary.BigEndian, &typeAndVersion) != nil {
		return nil, common.ErrNoClue
	} else if b[0]>>4&0xF > 4 || b[0]&0xF != 1 {
		return nil, errNotBittorrent
	}

	var extension uint8

	if binary.Read(buffer, binary.BigEndian, &extension) != nil {
		return nil, common.ErrNoClue
	} else if extension != 0 && extension != 1 {
		return nil, errNotBittorrent
	}

	for extension != 0 {
		if extension != 1 {
			return nil, errNotBittorrent
		}
		if binary.Read(buffer, binary.BigEndian, &extension) != nil {
			return nil, common.ErrNoClue
		}

		var length uint8
		if err := binary.Read(buffer, binary.BigEndian, &length); err != nil {
			return nil, common.ErrNoClue
		}
		if common.Error2(buffer.ReadBytes(int32(length))) != nil {
			return nil, common.ErrNoClue
		}
	}

	if common.Error2(buffer.ReadBytes(2)) != nil {
		return nil, common.ErrNoClue
	}

	var timestamp uint32
	if err := binary.Read(buffer, binary.BigEndian, &timestamp); err != nil {
		return nil, common.ErrNoClue
	}
	if math.Abs(float64(time.Now().UnixMicro()-int64(timestamp))) > float64(24*time.Hour) {
		return nil, errNotBittorrent
	}

	incStat(ctx, uuid)
	return &SniffHeader{}, nil
}
