package trivy

import (
	"bytes"
	"fmt"
	"os/exec"
)

func RunImageScan(image string) ([]byte, error) {
	cmd := exec.Command(
		"trivy",
		"image",
		"--quiet",
		"--format",
		"json",
		image,
	)

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy failed: %s", stderr.String())
	}

	return out.Bytes(), nil
}
