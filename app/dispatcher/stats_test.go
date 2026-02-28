package dispatcher_test

import (
	"testing"
	"time"

	. "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type TestCounter int64

func (c *TestCounter) Value() int64 {
	return int64(*c)
}

func (c *TestCounter) Add(v int64) int64 {
	x := int64(*c) + v
	*c = TestCounter(x)
	return x
}

func (c *TestCounter) Set(v int64) int64 {
	*c = TestCounter(v)
	return v
}

func TestStatsWriter(t *testing.T) {
	var c TestCounter
	writer := &SizeStatWriter{
		Counter: &c,
		Writer:  buf.Discard,
	}

	mb := buf.MergeBytes(nil, []byte("abcd"))
	common.Must(writer.WriteMultiBuffer(mb))

	mb = buf.MergeBytes(nil, []byte("efg"))
	common.Must(writer.WriteMultiBuffer(mb))

	if c.Value() != 7 {
		t.Fatal("unexpected counter value. want 7, but got ", c.Value())
	}
}

func TestRateLimitWriter(t *testing.T) {
	// 10KB/s limit, 10KB burst
	limiter := rate.NewLimiter(10*1024, 10*1024)
	writer := &RateLimitWriter{
		Writer:  buf.Discard,
		Limiter: limiter,
	}

	// Write 20KB — at 10KB/s this should take ~1 second
	data := make([]byte, 20*1024)
	mb := buf.MergeBytes(nil, data)

	start := time.Now()
	common.Must(writer.WriteMultiBuffer(mb))
	elapsed := time.Since(start)

	// Should take at least 900ms (10KB burst free, 10KB at 10KB/s = 1s, with some tolerance)
	if elapsed < 900*time.Millisecond {
		t.Fatalf("rate limit not effective: 20KB written in %v, expected >= 900ms", elapsed)
	}
	t.Logf("20KB at 10KB/s took %v (OK)", elapsed)
}

func TestRateLimitWriterNoThrottleSmallData(t *testing.T) {
	// 100KB/s limit, 100KB burst
	limiter := rate.NewLimiter(100*1024, 100*1024)
	writer := &RateLimitWriter{
		Writer:  buf.Discard,
		Limiter: limiter,
	}

	// Write 1KB — fits within burst, should be instant
	data := make([]byte, 1024)
	mb := buf.MergeBytes(nil, data)

	start := time.Now()
	common.Must(writer.WriteMultiBuffer(mb))
	elapsed := time.Since(start)

	if elapsed > 50*time.Millisecond {
		t.Fatalf("small write should be instant, took %v", elapsed)
	}
	t.Logf("1KB burst write took %v (OK)", elapsed)
}

func TestRateLimitWriterLargerThanBurst(t *testing.T) {
	// 10KB/s, burst only 2KB — buffer (8KB) > burst, must split WaitN
	limiter := rate.NewLimiter(10*1024, 2*1024)
	writer := &RateLimitWriter{
		Writer:  buf.Discard,
		Limiter: limiter,
	}

	data := make([]byte, 8*1024)
	mb := buf.MergeBytes(nil, data)

	start := time.Now()
	common.Must(writer.WriteMultiBuffer(mb))
	elapsed := time.Since(start)

	// 2KB burst free, remaining 6KB at 10KB/s ≈ 600ms
	if elapsed < 500*time.Millisecond {
		t.Fatalf("expected >= 500ms for 8KB with 2KB burst at 10KB/s, got %v", elapsed)
	}
	t.Logf("8KB with 2KB burst at 10KB/s took %v (OK)", elapsed)
}
