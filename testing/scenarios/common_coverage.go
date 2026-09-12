//go:build coverage
// +build coverage

package scenarios

import (
	"bytes"
	"os"
	"os/exec"
	"sync"

	"github.com/GFW-knocker/Xray-core/common/uuid"
)

// Tests that start several servers at once call BuildXray concurrently, so the
// build is guarded: without it every caller sees the os.Stat miss and they race
// to write the same output path, which fails outright on Windows.
var (
	buildXrayOnce sync.Once
	buildXrayErr  error
)

func BuildXray() error {
	buildXrayOnce.Do(func() {
		genTestBinaryPath()
		if _, err := os.Stat(testBinaryPath); err == nil {
			return
		}

		cmd := exec.Command("go", "test", "-tags", "coverage coveragemain", "-coverpkg", "github.com/GFW-knocker/Xray-core/...", "-c", "-o", testBinaryPath, GetSourcePath())
		buildXrayErr = cmd.Run()
	})
	return buildXrayErr
}

func RunXrayProtobuf(config []byte) *exec.Cmd {
	genTestBinaryPath()

	covDir := os.Getenv("XRAY_COV")
	os.MkdirAll(covDir, os.ModeDir)
	randomID := uuid.New()
	profile := randomID.String() + ".out"
	proc := exec.Command(testBinaryPath, "-config=stdin:", "-format=pb", "-test.run", "TestRunMainForCoverage", "-test.coverprofile", profile, "-test.outputdir", covDir)
	proc.Stdin = bytes.NewBuffer(config)
	proc.Stderr = os.Stderr
	proc.Stdout = os.Stdout

	return proc
}
