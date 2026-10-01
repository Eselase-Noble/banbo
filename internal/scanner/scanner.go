// Package scanner defines the Module contract that every scan check implements
// and the orchestrator that runs modules concurrently and collects their
// findings into one normalized, de-duplicated set.
package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/Eselase-Noble/banbo/internal/findings"
)

// Module is a single pluggable scan check (network, tls, http, dns, ...).
// Implementations must be safe to run concurrently and must respect ctx
// cancellation. A module returns findings and/or an error; an error does not
// abort the whole scan, it is recorded against that module.
type Module interface {
	Name() string
	Scan(ctx context.Context, t Target) ([]findings.Finding, error)
}

// ModuleError records that a module failed, without aborting the run.
type ModuleError struct {
	Module string `json:"module"`
	Err    string `json:"error"`
}

// Result is the full outcome of a scan: the normalized findings plus metadata
// useful for reporting (timing, per-module errors, severity summary).
type Result struct {
	Target    string             `json:"target"`
	Host      string             `json:"host"`
	StartedAt time.Time          `json:"started_at"`
	Duration  time.Duration      `json:"duration_ms"`
	Findings  []findings.Finding `json:"findings"`
	Summary   findings.Counts    `json:"summary"`
	Errors    []ModuleError      `json:"errors,omitempty"`
}

// Scanner runs a fixed set of modules against a target.
type Scanner struct {
	Modules     []Module
	Concurrency int // max modules running at once; 0 means "one per module"
}

// New builds a Scanner from the given modules.
func New(modules ...Module) *Scanner {
	return &Scanner{Modules: modules, Concurrency: len(modules)}
}

// Run executes every module concurrently (bounded by Concurrency), collects the
// results, and returns a normalized, de-duplicated Result. The clock is passed
// in so callers (and tests) control timing.
func (s *Scanner) Run(ctx context.Context, t Target, now func() time.Time) Result {
	start := now()
	limit := s.Concurrency
	if limit <= 0 {
		limit = 1
	}
	sem := make(chan struct{}, limit)

	var (
		mu   sync.Mutex
		all  []findings.Finding
		errs []ModuleError
		wg   sync.WaitGroup
	)

	for _, m := range s.Modules {
		wg.Add(1)
		go func(m Module) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				errs = append(errs, ModuleError{Module: m.Name(), Err: ctx.Err().Error()})
				mu.Unlock()
				return
			}

			fs, err := m.Scan(ctx, t)
			mu.Lock()
			if err != nil {
				errs = append(errs, ModuleError{Module: m.Name(), Err: err.Error()})
			}
			all = append(all, fs...)
			mu.Unlock()
		}(m)
	}
	wg.Wait()

	deduped := findings.Dedupe(all)
	return Result{
		Target:    t.Raw,
		Host:      t.Host,
		StartedAt: start,
		Duration:  now().Sub(start),
		Findings:  deduped,
		Summary:   findings.Summarize(deduped),
		Errors:    errs,
	}
}
