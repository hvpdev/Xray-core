package bittorrent

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cloudflare/ahocorasick"
	"github.com/xtls/xray-core/common/log"

	"github.com/glenn-brown/golang-pkg-pcre/src/pkg/pcre"
	"github.com/google/gonids"
)

type filterRule struct {
	rule         *gonids.Rule
	contentBytes [][]byte
	pcrePatterns []pcre.Regexp
	depth        int
	offset       int
}

func (r *filterRule) searchArea(data []byte) []byte {
	searchArea := data
	if r.offset > 0 && len(searchArea) > r.offset {
		searchArea = searchArea[r.offset:]
	}
	if r.depth > 0 && len(searchArea) > r.depth {
		searchArea = searchArea[:r.depth]
	}
	return searchArea
}

func parseRules(filename string) ([]filterRule, error) {
	file, err := os.Open(filename)
	if err != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Error,
			Content:  fmt.Sprintf("Failed to open file: %v", err),
		})
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	var (
		rules   []filterRule
		lineNum = 0
		scanner = bufio.NewScanner(file)
	)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// Parse rule with gonids
		rule, err := gonids.ParseRule(line)
		if err != nil {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Error,
				Content:  fmt.Sprintf("Failed to parse rule: %v", err),
			})
			continue
		}

		r := filterRule{rule: rule}
		// Extract content patterns
		for _, content := range rule.Contents() {
			// Convert hex values to bytes
			r.contentBytes = append(r.contentBytes, content.Pattern)

			// Extract depth and offset from options
			for _, option := range content.Options {
				if option.Name == "depth" {
					r.depth, err = strconv.Atoi(option.Value)
					if err != nil {
						log.Record(&log.GeneralMessage{
							Severity: log.Severity_Error,
							Content:  fmt.Sprintf("Failed to convert depth to int: %v", err),
						})
						continue
					}
				} else if option.Name == "offset" {
					r.offset, err = strconv.Atoi(option.Value)
					if err != nil {
						log.Record(&log.GeneralMessage{
							Severity: log.Severity_Error,
							Content:  fmt.Sprintf("Failed to convert offset to int: %v", err),
						})
						continue
					}
				}
			}
		}

		// Extract PCRE patterns
		for _, pcrePattern := range rule.PCREs() {
			pcreStr := string(pcrePattern.Pattern)
			compiled, err := pcre.Compile(pcreStr, 0)
			if err == nil {
				r.pcrePatterns = append(r.pcrePatterns, compiled)
			} else {
				log.Record(&log.GeneralMessage{
					Severity: log.Severity_Error,
					Content:  fmt.Sprintf("Failed to compile PCRE pattern: %v", err),
				})
			}
		}

		// Add rule only if there is at least one pattern
		if len(r.contentBytes) > 0 || len(r.pcrePatterns) > 0 {
			rules = append(rules, r)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Error,
			Content:  fmt.Sprintf("Failed to read file: %v", err),
		})
		return nil, fmt.Errorf("read file: %w", err)
	}

	return rules, nil
}

func parseRulesFromFiles(rulesFilePath []string) ([]filterRule, error) {
	var rules []filterRule
	for _, rulesFile := range rulesFilePath {
		rs, err := parseRules(rulesFile)
		if err != nil {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Error,
				Content:  fmt.Sprintf("Failed to parse rules: %v", err),
			})
			return nil, fmt.Errorf("parse rules for %s: %w", rulesFile, err)
		}
		rules = append(rules, rs...)
	}
	return rules, nil
}

type ruleMatcher struct {
	m            *ahocorasick.Matcher
	patterToRule map[int]int
	rules        []filterRule
}

func newRuleMatcher(rules []filterRule) (*ruleMatcher, error) {
	var (
		contentPatterns []string
		patterToRule    = make(map[int]int)
	)
	for i, rule := range rules {
		for _, pattern := range rule.contentBytes {
			// Add only non-empty patterns
			if len(pattern) > 0 {
				contentPatterns = append(contentPatterns, string(pattern))
				patterToRule[len(contentPatterns)-1] = i
			}
		}
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  fmt.Sprintf("Loaded content patterns for Aho-Corasick: %d", len(contentPatterns)),
	})

	var matcher *ahocorasick.Matcher
	if len(contentPatterns) > 0 {
		matcher = ahocorasick.NewStringMatcher(contentPatterns)
	} else {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Warning,
			Content:  "No content patterns found for Aho-Corasick",
		})
		return nil, errors.New("no content patterns found for Aho-Corasick")
	}

	return &ruleMatcher{
		m:            matcher,
		patterToRule: patterToRule,
		rules:        rules,
	}, nil
}

// Is not multi-thread safe
func (rm *ruleMatcher) match(data []byte) *filterRule {
	// Use Aho-Corasick for fast pattern matching
	matches := rm.m.Match(data)
	// Check content patterns to avoid false positives
	for _, match := range matches {
		rule := &rm.rules[rm.patterToRule[match]]
		searchArea := rule.searchArea(data)

		if len(rule.contentBytes) > 0 {
			for _, pattern := range rule.contentBytes {
				if bytes.Contains(searchArea, pattern) {
					return rule
				}
			}
		}

	}

	// Check PCRE patterns for each rule
	for _, rule := range rm.rules {
		searchArea := string(rule.searchArea(data))
		for _, pattern := range rule.pcrePatterns {
			if pattern.MatcherString(searchArea, 0).Matches() {
				return &rule
			}
		}
	}

	return nil
}
