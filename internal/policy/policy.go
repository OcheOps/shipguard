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

	// First pass: blockers only
	for _, f := range findings {
		if env == EnvProd && f.Severity == normalize.SevCritical && f.RuntimeRelevant {
			reasons = append(reasons,
				"CRITICAL vulnerability at runtime: "+f.Package+" ("+f.ID+")",
			)
			if f.FixAvailable {
				reasons = append(reasons,
					"Fix available: upgrade "+f.Package+" to "+f.Fixed,
				)
			} else {
				reasons = append(reasons,
					"No fix available yet (mitigation required)",
				)
			}
			return VerdictBlock, reasons
		}

		if env == EnvProd && f.Severity == normalize.SevHigh && f.RuntimeRelevant && f.FixAvailable {
			reasons = append(reasons,
				"HIGH vulnerability with available fix: "+f.Package+" ("+f.ID+")",
				"Fix available: upgrade "+f.Package+" to "+f.Fixed,
			)
			return VerdictBlock, reasons
		}
	}

	// Second pass: warnings
	for _, f := range findings {
		if f.Severity == normalize.SevMedium {
			reasons = append(reasons,
				"MEDIUM vulnerability present: "+f.Package+" ("+f.ID+")",
			)
		}
	}

	if len(reasons) > 0 {
		return VerdictWarn, reasons
	}

	return VerdictDeploy, []string{"No policy-violating findings detected"}
}
