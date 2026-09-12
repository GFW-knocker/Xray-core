//go:build !coverage
// +build !coverage

package scenarios

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sync"
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

		fmt.Printf("Building Xray into path (%s)\n", testBinaryPath)
		cmd := exec.Command("go", "build", "-o="+testBinaryPath, GetSourcePath())
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		buildXrayErr = cmd.Run()
	})
	return buildXrayErr
}

func RunXrayProtobuf(config []byte) *exec.Cmd {
	genTestBinaryPath()
	proc := exec.Command(testBinaryPath, "-config=stdin:", "-format=pb")
	proc.Stdin = bytes.NewBuffer(config)
	proc.Stderr = os.Stderr
	proc.Stdout = os.Stdout

	return proc
}
