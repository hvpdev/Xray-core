package dispatcher

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
	"golang.org/x/time/rate"
)

type SizeStatWriter struct {
	Counter stats.Counter
	Writer  buf.Writer
}

func (w *SizeStatWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.Counter.Add(int64(mb.Len()))
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *SizeStatWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *SizeStatWriter) Interrupt() {
	common.Interrupt(w.Writer)
}

// RateLimitWriter wraps a buf.Writer with a rate limiter (golang.org/x/time/rate).
type RateLimitWriter struct {
	Writer  buf.Writer
	Limiter *rate.Limiter
}

func (w *RateLimitWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	n := int(mb.Len())
	burst := w.Limiter.Burst()
	// Split into burst-sized chunks because WaitN fails if n > burst.
	for n > 0 {
		take := burst
		if take > n {
			take = n
		}
		if err := w.Limiter.WaitN(context.Background(), take); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
		n -= take
	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *RateLimitWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *RateLimitWriter) Interrupt() {
	common.Interrupt(w.Writer)
}
