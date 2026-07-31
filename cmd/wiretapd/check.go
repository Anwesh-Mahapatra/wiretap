package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"wiretap/internal/langfuse"
	"wiretap/internal/litellm"
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

	// --- content plane ---
	bcfg := cfg.bootstrapConfig()
	templateExists, templateErr := es.TemplateExists(ctx, bcfg)
	templateOK := templateErr == nil && templateExists
	templateDetail := errDetail(templateErr)
	if templateErr == nil && !templateExists {
		templateDetail = "not found -- run `wiretapd bootstrap`"
	}
	results = append(results, checkResult{"langfuse index template exists", templateOK, templateDetail})

	info, statErr := os.Stat(cfg.archivePath)
	archiveOK := statErr == nil && info.Size() > 0
	archiveDetail := errDetail(statErr)
	if statErr == nil && info.Size() == 0 {
		archiveDetail = "exists but is empty -- has tracepump/wiretapd's fetch stage run yet?"
	}
	results = append(results, checkResult{"langfuse archive readable", archiveOK, archiveDetail})

	// --- gateway plane preflight ---
	//
	// Each of these has a distinct failure mode that the others cannot
	// stand in for, which is why they are four rows rather than one
	// "gateway ok". A reachable spend API with no template still indexes
	// nothing; a present template with an unreadable archive still
	// indexes nothing; and both look identical from the outside.
	if cfg.litellmMasterKey == "" {
		results = append(results, checkResult{"litellm master key set", false,
			"LITELLM_MASTER_KEY is empty -- the spend API is the gateway plane's only source and it requires the master key"})
	} else {
		results = append(results, checkResult{"litellm master key set", true, ""})
	}

	// Ping hits the authenticated spend endpoint, not /health/liveliness:
	// liveliness needs no auth and answers 200 for a completely wrong
	// master key, which makes it useless as a preflight for the thing
	// most likely to be misconfigured.
	llErr := cfg.litellmClient().Ping(ctx)
	results = append(results, checkResult{"litellm spend api reachable", llErr == nil, litellmErrDetail(llErr)})

	gwBcfg := cfg.gatewayBootstrapConfig()
	gwTemplateExists, gwTemplateErr := es.TemplateExists(ctx, gwBcfg)
	gwTemplateOK := gwTemplateErr == nil && gwTemplateExists
	gwTemplateDetail := errDetail(gwTemplateErr)
	if gwTemplateErr == nil && !gwTemplateExists {
		gwTemplateDetail = "not found -- run `wiretapd bootstrap`"
	}
	results = append(results, checkResult{"gateway index template exists", gwTemplateOK, gwTemplateDetail})

	// The gateway archive is allowed to be *absent* on a stack that has
	// never run the gateway fetcher -- that is a "not started yet" state,
	// not a broken one. It is only a failure if it exists and cannot be
	// read.
	gwInfo, gwStatErr := os.Stat(cfg.gatewayArchivePath)
	gwArchiveOK := gwStatErr == nil || os.IsNotExist(gwStatErr)
	gwArchiveDetail := ""
	switch {
	case gwStatErr != nil && os.IsNotExist(gwStatErr):
		gwArchiveDetail = "not created yet -- normal until the gateway fetcher has run once"
	case gwStatErr != nil:
		gwArchiveDetail = errDetail(gwStatErr)
	case gwInfo.Size() == 0:
		gwArchiveDetail = "exists but is empty -- has the gateway fetcher run yet?"
	}
	results = append(results, checkResult{"gateway archive readable", gwArchiveOK, gwArchiveDetail})

	// Path isolation is a correctness precondition, not a preference:
	// two writers on one archive is the duplicate-writer race arch.md
	// describes, and its symptom is silently lost or duplicated data.
	isoErr := cfg.validatePathIsolation()
	results = append(results, checkResult{"source paths isolated", isoErr == nil, errDetail(isoErr)})

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

// litellmErrDetail turns a spend-API failure into something actionable.
// A bare "401 Unauthorized" sends people to check the wrong key: this
// stack has several, and only one of them is the proxy master key.
func litellmErrDetail(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case litellm.IsAuthError(err):
		return "rejected -- check LITELLM_MASTER_KEY (this is the proxy master key, not a virtual key or the Groq key)"
	case litellm.IsNotFound(err):
		return "endpoint not found -- this LiteLLM build may predate /spend/logs/v2"
	case litellm.IsTransportError(err):
		return "unreachable -- check LITELLM_BASE_URL (inside a container this must be the compose service name, not localhost)"
	}
	return errDetail(err)
}
