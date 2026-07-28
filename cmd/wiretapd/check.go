package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"wiretap/internal/langfuse"
)

type checkResult struct {
	name   string
	ok     bool
	detail string
}

// cmdCheck runs the four preflight checks named in the task spec -- can it
// reach Langfuse, can it reach Elasticsearch, does the index template
// exist, is the archive readable and non-empty -- and prints a pass/fail
// table. This is meant to be the first thing run when something's wrong:
// it turns "the pipeline is broken" into "which of four specific things is
// broken."
func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var results []checkResult

	lf := cfg.langfuseClient()
	_, lfErr := lf.ListTraces(ctx, langfuse.ListTracesParams{Limit: 1})
	results = append(results, checkResult{"langfuse reachable", lfErr == nil, errDetail(lfErr)})

	es := cfg.esClient()
	esErr := es.Ping(ctx)
	results = append(results, checkResult{"elasticsearch reachable", esErr == nil, errDetail(esErr)})

	bcfg := cfg.bootstrapConfig()
	templateExists, templateErr := es.TemplateExists(ctx, bcfg)
	templateOK := templateErr == nil && templateExists
	templateDetail := errDetail(templateErr)
	if templateErr == nil && !templateExists {
		templateDetail = "not found -- run `wiretapd bootstrap`"
	}
	results = append(results, checkResult{"index template exists", templateOK, templateDetail})

	info, statErr := os.Stat(cfg.archivePath)
	archiveOK := statErr == nil && info.Size() > 0
	archiveDetail := errDetail(statErr)
	if statErr == nil && info.Size() == 0 {
		archiveDetail = "exists but is empty -- has tracepump/wiretapd's fetch stage run yet?"
	}
	results = append(results, checkResult{"archive readable and non-empty", archiveOK, archiveDetail})

	allOK := printCheckTable(results)
	if !allOK {
		return fmt.Errorf("one or more preflight checks failed")
	}
	return nil
}

func printCheckTable(results []checkResult) (allOK bool) {
	allOK = true
	fmt.Printf("%-32s %-6s %s\n", "CHECK", "STATUS", "DETAIL")
	for _, r := range results {
		status := "PASS"
		if !r.ok {
			status = "FAIL"
			allOK = false
		}
		fmt.Printf("%-32s %-6s %s\n", r.name, status, r.detail)
	}
	return allOK
}

func errDetail(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
