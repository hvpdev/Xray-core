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

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "bittorrent"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotBittorrent = errors.New("not bittorrent header")

func SniffBittorrent(ctx context.Context, b []byte) (*SniffHeader, error) {
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Debug,
		Content:  fmt.Sprintf("Bittorrent: %d bytes", len(b)),
	})
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Debug,
			Content:  fmt.Sprintf("UTP: inbound: %s, gateway: %s", inbound.Source.NetAddr(), inbound.Gateway.NetAddr()),
		})
		if tcpAnalyzer.IsIPWhitelisted(inbound.Source.NetAddr()) ||
			tcpAnalyzer.IsIPWhitelisted(inbound.Gateway.NetAddr()) {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Debug,
				Content:  "Bittorrent: IP is whitelisted",
			})
			return nil, errNotBittorrent
		}
	}

	ok, rule := tcpAnalyzer.Match(b)
	if ok {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Debug,
			Content:  fmt.Sprintf("Bittorrent: matched rule: %s", rule),
		})
		return &SniffHeader{}, nil
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Debug,
		Content:  "Bittorrent: not matched rule, continue to sniff",
	})

	if b[0] == 19 && string(b[1:20]) == "BitTorrent protocol" {
		return &SniffHeader{}, nil
	}

	return nil, errNotBittorrent
}

func SniffUTP(ctx context.Context, b []byte) (*SniffHeader, error) {
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Debug,
		Content:  fmt.Sprintf("UTP: %d bytes", len(b)),
	})
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Debug,
			Content:  fmt.Sprintf("UTP: inbound: %s, gateway: %s", inbound.Source.NetAddr(), inbound.Gateway.NetAddr()),
		})
		if udpAnalyzer.IsIPWhitelisted(inbound.Source.NetAddr()) ||
			udpAnalyzer.IsIPWhitelisted(inbound.Gateway.NetAddr()) {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Debug,
				Content:  "UTP: IP is whitelisted",
			})
			return nil, errNotBittorrent
		}
	}

	ok, rule := udpAnalyzer.Match(b)
	if ok {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Debug,
			Content:  fmt.Sprintf("UTP: matched rule: %s", rule),
		})
		return &SniffHeader{}, nil
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Debug,
		Content:  "UTP: not matched rule, continue to sniff",
	})

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

	return &SniffHeader{}, nil
}
