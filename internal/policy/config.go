package policy

type Config struct {
	Env   Env   `yaml:"env"`
	Rules Rules `yaml:"rules"`
}

type Rules struct {
	Block []Rule `yaml:"block"`
	Warn  []Rule `yaml:"warn"`
}

type Rule struct {
	Severity     string `yaml:"severity"`
	FixAvailable *bool  `yaml:"fix_available,omitempty"`
}
