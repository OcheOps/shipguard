package main

import (
	"github.com/spf13/pflag"

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
  shipguard scan [IMAGE] --env <prod|staging|dev> --policy policy.yaml
  shipguard scan --input <trivy.json> --env <prod|staging|dev> --policy policy.yaml

Exit codes:
  0 = DEPLOY
  1 = BLOCK
  2 = WARN
`)
}

func runScan(args []string) {
	fs := pflag.NewFlagSet("scan", pflag.ExitOnError)
	fs.SetInterspersed(true)

	input := fs.String("input", "", "Path to Trivy JSON report file")
	envStr := fs.String("env", "prod", "Environment: prod|staging|dev")
	policyPath := fs.String("policy", "", "Path to policy.yaml")

	_ = fs.Parse(args)

	// Validate env
	env := policy.Env(strings.ToLower(strings.TrimSpace(*envStr)))
	if env != policy.EnvProd && env != policy.EnvStaging && env != policy.EnvDev {
		fmt.Println("ERROR: --env must be one of: prod|staging|dev")
		os.Exit(2)
	}

	// Policy is mandatory
	if strings.TrimSpace(*policyPath) == "" {
		fmt.Println("ERROR: --policy is required")
		os.Exit(2)
	}

	cfg, err := policy.LoadPolicy(*policyPath)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(2)
	}

	var report *trivy.Report

	// Case 1: input file
	if strings.TrimSpace(*input) != "" {
		report, err = trivy.LoadReportFromFile(*input)
		if err != nil {
			fmt.Println("ERROR:", err)
			os.Exit(2)
		}
	} else {
		// Case 2: image name
		if fs.NArg() < 1 {
			fmt.Println("ERROR: provide either --input <file> or an image name")
			os.Exit(2)
		}

		image := fs.Arg(0)
		data, err := trivy.RunImageScan(image)
		if err != nil {
			// Graceful WARN on Trivy failure
			fmt.Println("SHIPGUARD VERDICT")
			fmt.Println("----------------")
			fmt.Println("WARN\n")
			fmt.Println("Scan could not complete:")
			fmt.Println("-", err.Error())
			fmt.Println("\nReason:")
			fmt.Println("- Trivy scan failed or timed out; image risk could not be fully evaluated")
			fmt.Println("- Proceed with caution or rerun scan with more resources")
			os.Exit(2)
		}

		report, err = trivy.LoadReportFromBytes(data)
		if err != nil {
			fmt.Println("ERROR:", err)
			os.Exit(2)
		}
	}

	findings := normalize.Normalize(report)

	// 🔑 THIS is the correct call now
	res := decision.DecideWithPolicy(cfg, findings)

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
