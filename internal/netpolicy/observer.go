package netpolicy

import "time"

type observation struct {
	Start, End       time.Time
	Seen             map[string]int
	Complete, Closed bool
}
type monitor interface{ stop() observation }
