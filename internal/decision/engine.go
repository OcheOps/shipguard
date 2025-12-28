package decision

import (
	"fmt"
	"strings"

	"github.com/OcheOps/shipguard/internal/normalize"
	"github.com/OcheOps/shipguard/internal/policy"
)

type Result struct {
	Verdict policy.Verdict
	Reasons []string
	Summary string
}

// ✅ THIS is what main.go is calling
func DecideWithPolicy(cfg *policy.Config, findings []normalize.Finding) Result {
	verdict, reasons := policy.EvaluateWithConfig(cfg, findings)

	summary := fmt.Sprintf(
		"Findings: %d | Env: %s | Verdict: %s",
		len(findings), cfg.Env, verdict,
	)

	return Result{
		Verdict: verdict,
		Reasons: reasons,
		Summary: summary,
	}
}

func FormatHuman(r Result) string {
	var b strings.Builder
	b.WriteString("SHIPGUARD VERDICT\n")
	b.WriteString("----------------\n")
	b.WriteString(string(r.Verdict))
	b.WriteString("\n\n")
	b.WriteString(r.Summary)
	b.WriteString("\n\n")

	if len(r.Reasons) > 0 {
		b.WriteString("Reasons:\n")
		for _, s := range r.Reasons {
			b.WriteString("- ")
			b.WriteString(s)
			b.WriteString("\n")
		}
	} else {
		b.WriteString("Reasons:\n- No policy-violating findings detected.\n")
	}

	return b.String()
}
