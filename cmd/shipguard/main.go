package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/OcheOps/shipguard/internal/decision"
	"github.com/OcheOps/shipguard/internal/normalize"
	"github.com/OcheOps/shipguard/internal/policy"
	"github.com/OcheOps/shipguard/internal/trivy"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`shipguard - container deployment decision engine

Usage:
  shipguard scan --input <trivy.json> --env <prod|staging|dev>

Exit codes:
  0 = DEPLOY
  1 = BLOCK
  2 = WARN
`)
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	input := fs.String("input", "", "Path to Trivy JSON report file")
	envStr := fs.String("env", "prod", "Environment: prod|staging|dev")
	_ = fs.Parse(args)

	if strings.TrimSpace(*input) == "" {
		fmt.Println("ERROR: --input is required")
		os.Exit(2)
	}

	env := policy.Env(strings.ToLower(strings.TrimSpace(*envStr)))
	if env != policy.EnvProd && env != policy.EnvStaging && env != policy.EnvDev {
		fmt.Println("ERROR: --env must be one of: prod|staging|dev")
		os.Exit(2)
	}

	report, err := trivy.LoadReportFromFile(*input)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(2)
	}

	findings := normalize.Normalize(report)
	res := decision.Decide(env, findings)

	fmt.Println(decision.FormatHuman(res))

	switch res.Verdict {
	case policy.VerdictDeploy:
		os.Exit(0)
	case policy.VerdictBlock:
		os.Exit(1)
	case policy.VerdictWarn:
		os.Exit(2)
	default:
		os.Exit(2)
	}
}
