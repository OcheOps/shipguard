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
func EvaluateWithConfig(cfg *Config, findings []normalize.Finding) (Verdict, []string) {
	reasons := []string{}

	// BLOCK rules
	for _, f := range findings {
		for _, r := range cfg.Rules.Block {
			if string(f.Severity) != r.Severity {
				continue
			}
			if r.FixAvailable != nil && *r.FixAvailable != f.FixAvailable {
				continue
			}

			reasons = append(reasons,
				string(f.Severity)+" vulnerability: "+f.Package+" ("+f.ID+")",
			)
			if f.FixAvailable {
				reasons = append(reasons, "Fix available: upgrade "+f.Package+" to "+f.Fixed)
			}
			return VerdictBlock, reasons
		}
	}

	// WARN rules
	for _, f := range findings {
		for _, r := range cfg.Rules.Warn {
			if string(f.Severity) == r.Severity {
				reasons = append(reasons,
					string(f.Severity)+" vulnerability present: "+f.Package+" ("+f.ID+")",
				)
			}
		}
	}

	if len(reasons) > 0 {
		return VerdictWarn, reasons
	}

	return VerdictDeploy, []string{"No policy-violating findings detected"}
}
