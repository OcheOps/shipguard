package policy

import "github.com/OcheOps/shipguard/internal/normalize"

type Env string

const (
	EnvProd    Env = "prod"
	EnvStaging Env = "staging"
	EnvDev     Env = "dev"
)

type Verdict string

const (
	VerdictDeploy Verdict = "DEPLOY"
	VerdictWarn   Verdict = "WARN"
	VerdictBlock  Verdict = "BLOCK"
)

type RuleSet struct {
	Env Env
}

// MVP policy (simple and explainable):
// - prod: block CRITICAL
// - prod: block HIGH when fix is available
// - warn on MEDIUM
func Evaluate(env Env, findings []normalize.Finding) (Verdict, []string) {
	reasons := []string{}
	verdict := VerdictDeploy

	for _, f := range findings {
		if env == EnvProd && f.Severity == normalize.SevCritical && f.RuntimeRelevant {
			verdict = VerdictBlock
			reasons = append(reasons, "CRITICAL vulnerability at runtime: "+f.Package+" ("+f.ID+")")
			if f.FixAvailable {
				reasons = append(reasons, "Fix available: upgrade "+f.Package+" to "+f.Fixed)
			} else {
				reasons = append(reasons, "No fix available yet (mitigation required)")
			}
			continue
		}

		if env == EnvProd && f.Severity == normalize.SevHigh && f.RuntimeRelevant && f.FixAvailable {
			if verdict != VerdictBlock {
				verdict = VerdictBlock
			}
			reasons = append(reasons, "HIGH vulnerability with available fix: "+f.Package+" ("+f.ID+")")
			reasons = append(reasons, "Fix available: upgrade "+f.Package+" to "+f.Fixed)
			continue
		}

		if f.Severity == normalize.SevMedium {
			if verdict == VerdictDeploy {
				verdict = VerdictWarn
			}
			reasons = append(reasons, "MEDIUM vulnerability present: "+f.Package+" ("+f.ID+")")
		}
	}

	// keep reasons short for human output (top 3-ish)
	if len(reasons) > 6 {
		reasons = reasons[:6]
	}
	return verdict, reasons
}
