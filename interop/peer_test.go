// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop exchanges SCHC messages with openschc, the Python
// reference implementation, running in Docker. The tests are off unless
// SIGMA_SCHC_INTEROP=1.
package interop

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// The reference peers' images, built from the directory named: openschc at
// commit 58293f71 (2025-12-16), and schc-over-sigfox, the RFC 9442
// authors' implementation, at commit 1ec0b723 (2023-02-18).
var (
	openschc = peerImage{"sigma-schc-interop:openschc-58293f71", "peer"}
	sigfoxRI = peerImage{"sigma-schc-interop:schc-over-sigfox-1ec0b723", "sigfoxpeer"}
)

type peerImage struct{ tag, dir string }

// envVar turns the tests on.
const envVar = "SIGMA_SCHC_INTEROP"

var (
	buildMu   sync.Mutex
	built     = map[string]error{}
	buildDone = map[string]bool{}
)

// needDocker skips the test unless the environment variable is 1 and
// Docker answers, and builds the peer image once per run.
func needDocker(t *testing.T, img peerImage) {
	t.Helper()
	if os.Getenv(envVar) != "1" {
		t.Skip("set " + envVar + "=1 to run the interop tests (needs Docker)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker is not running")
	}
	buildMu.Lock()
	defer buildMu.Unlock()
	if !buildDone[img.tag] {
		buildDone[img.tag] = true
		if out, err := exec.Command("docker", "build", "-q", "-t", img.tag, img.dir).CombinedOutput(); err != nil {
			built[img.tag] = fmt.Errorf("docker build: %v\n%s", err, out)
		}
	}
	if err := built[img.tag]; err != nil {
		t.Fatal(err)
	}
}

// peer is a reference implementation running in a container: standard
// input takes JSON commands, "PEER " lines come back.
type peer struct {
	t     *testing.T
	name  string
	cmd   *exec.Cmd
	stdin io.WriteCloser
	lines chan string

	mu  sync.Mutex
	log []string
}

// startPeer runs openschc.
func startPeer(t *testing.T) *peer { t.Helper(); return startImage(t, openschc) }

func startImage(t *testing.T, img peerImage) *peer {
	t.Helper()
	needDocker(t, img)
	p := &peer{t: t, name: fmt.Sprintf("sigma-schc-%d", time.Now().UnixNano()), lines: make(chan string, 4096)}
	p.cmd = exec.Command("docker", "run", "--rm", "-i", "--network", "none", "--name", p.name, img.tag)
	var err error
	if p.stdin, err = p.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	r, w := io.Pipe()
	p.cmd.Stdout, p.cmd.Stderr = w, w
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for sc.Scan() {
			line := sc.Text()
			p.mu.Lock()
			p.log = append(p.log, line)
			p.mu.Unlock()
			if s, ok := strings.CutPrefix(line, "PEER "); ok {
				p.lines <- s
			}
		}
	}()
	go func() { _ = p.cmd.Wait(); _ = w.Close() }()
	t.Cleanup(func() {
		_, _ = io.WriteString(p.stdin, "quit\n")
		_ = p.stdin.Close()
		_ = exec.Command("docker", "stop", "-t", "2", p.name).Run()
		if t.Failed() || os.Getenv(envVar+"_LOG") == "1" {
			t.Logf("peer output:\n%s", p.output())
		}
	})
	return p
}

func (p *peer) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.log, "\n")
}

// do sends one command and returns the peer's answer lines up to "done";
// an error from the peer fails the test.
func (p *peer) do(cmd map[string]any) []string {
	p.t.Helper()
	got, errLine := p.try(cmd)
	if errLine != "" {
		p.t.Fatalf("peer: %s (command %v)", errLine, cmd)
	}
	return got
}

// try is do that returns the peer's error line instead of failing.
func (p *peer) try(cmd map[string]any) (got []string, errLine string) {
	p.t.Helper()
	b, err := json.Marshal(cmd)
	if err != nil {
		p.t.Fatal(err)
	}
	if _, err := io.WriteString(p.stdin, string(b)+"\n"); err != nil {
		p.t.Fatalf("peer stdin: %v", err)
	}
	deadline := time.After(60 * time.Second)
	for {
		select {
		case l := <-p.lines:
			if l == "done" {
				return got, errLine
			}
			if strings.HasPrefix(l, "error") {
				errLine = l
				continue
			}
			got = append(got, l)
		case <-deadline:
			p.t.Fatalf("peer did not answer %s within 60s", b)
			return nil, ""
		}
	}
}

// setup gives the peer its rules (openschc's own format), its role
// ("device" sends up, "core" sends down) and its MTU in bits.
func (p *peer) setup(role string, rules any, mtu int) {
	p.t.Helper()
	p.do(map[string]any{"cmd": "setup", "role": role, "rules": rules, "mtu": mtu})
}

// tx collects the SCHC messages the peer sent among answer lines.
func tx(t *testing.T, lines []string) [][]byte {
	t.Helper()
	var out [][]byte
	for _, l := range lines {
		if s, ok := strings.CutPrefix(l, "tx "); ok {
			b, err := hex.DecodeString(s)
			if err != nil {
				t.Fatalf("peer tx %q: %v", s, err)
			}
			out = append(out, b)
		}
	}
	return out
}

// packets collects the packets the peer delivered among answer lines.
func packets(t *testing.T, lines []string) [][]byte {
	t.Helper()
	var out [][]byte
	for _, l := range lines {
		if s, ok := strings.CutPrefix(l, "packet "); ok {
			b, err := hex.DecodeString(s)
			if err != nil {
				t.Fatalf("peer packet %q: %v", s, err)
			}
			out = append(out, b)
		}
	}
	return out
}
