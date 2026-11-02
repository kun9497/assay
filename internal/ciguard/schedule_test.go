package ciguard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// QA 2026-11-02 #18: both scheduled workflows sat on minute 0 (`0 6 * * *`,
// `0 21 * * 0`), where GitHub's queue of scheduled runs is longest, and
// started hours late -- every nightly from 2026-10-13 to 11-02 by 4.2 to
// 7.6 hours, the weekly by 2 to 3.5 -- so a comment that read the cron as a
// start time ("Monday 06:00 KST") was wrong by hours and the external
// Monday review had fifty minutes of margin. The crons moved to 05:17 and
// 20:23. This holds them off minute 0, because the next person to touch a
// schedule will reach for a round number.

// ghSchedule reads `on` as a node, because Actions allows `on: push` and
// `on: [push, pull_request]` as well as the mapping that carries a schedule.
type ghSchedule struct {
	On yaml.Node `yaml:"on"`
}

type ghOnBlock struct {
	Schedule []struct {
		Cron string `yaml:"cron"`
	} `yaml:"schedule"`
}

var cronLine = regexp.MustCompile(`(?m)^\s*-\s*cron:`)

// scheduleProblems checks one workflow file's source and returns its problems
// and the number of crons it judged.
func scheduleProblems(file string, src []byte) ([]string, int, error) {
	var wf ghSchedule
	if err := yaml.Unmarshal(src, &wf); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", file, err)
	}
	var on ghOnBlock
	if wf.On.Kind == yaml.MappingNode {
		if err := wf.On.Decode(&on); err != nil {
			return nil, 0, fmt.Errorf("%s: %w", file, err)
		}
	}
	var out []string
	for _, s := range on.Schedule {
		f := strings.Fields(s.Cron)
		if len(f) != 5 {
			out = append(out, fmt.Sprintf("%s: cron %q does not have five fields", file, s.Cron))
			continue
		}
		// The minute field fires on 0 when it is 0, every minute, a list
		// starting at 0, or a step from 0.
		if f[0] == "0" || f[0] == "*" || strings.HasPrefix(f[0], "0,") || strings.HasPrefix(f[0], "*/") {
			out = append(out, fmt.Sprintf("%s: cron %q fires on minute 0, where GitHub's queue starts scheduled runs hours late; pick another minute (QA 2026-11-02 #18)", file, s.Cron))
		}
	}
	// A cron the parse never reaches -- under a key that is not on.schedule
	// -- is reported, not passed.
	if raw := len(cronLine.FindAll(src, -1)); raw != len(on.Schedule) {
		out = append(out, fmt.Sprintf("%s: %d cron lines in the text, %d parsed under on.schedule", file, raw, len(on.Schedule)))
	}
	return out, len(on.Schedule), nil
}

func TestNoScheduledWorkflowFiresOnMinuteZero(t *testing.T) {
	dir := filepath.Join(repoRoot, ".github", "workflows")
	files, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	perFile := map[string]int{}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		got, n, err := scheduleProblems(filepath.Base(f), src)
		if err != nil {
			t.Fatal(err)
		}
		perFile[filepath.Base(f)] = n
		for _, p := range got {
			t.Error(p)
		}
	}
	// The two scheduled workflows. Without this a parse that found no
	// schedule would pass every workflow.
	for _, f := range []string{"db-publish.yml", "scanner-diff.yml"} {
		if perFile[f] != 1 {
			t.Errorf("%s: judged %d crons, want 1", f, perFile[f])
		}
	}
}

func TestScheduleGuardRejects(t *testing.T) {
	wf := func(cron string) []byte {
		return []byte("on:\n  schedule:\n    - cron: \"" + cron + "\"\njobs: {}\n")
	}
	minuteZero := func(cron string) string {
		return "t.yml: cron \"" + cron + "\" fires on minute 0, where GitHub's queue starts scheduled runs hours late; pick another minute (QA 2026-11-02 #18)"
	}
	cases := []struct {
		name  string
		src   []byte
		crons int
		want  []string
	}{
		{"well formed", wf("17 5 * * *"), 1, nil},
		{"minute 0", wf("0 6 * * *"), 1, []string{minuteZero("0 6 * * *")}},
		{"every minute", wf("* 6 * * *"), 1, []string{minuteZero("* 6 * * *")}},
		{"a list starting at 0", wf("0,30 6 * * *"), 1, []string{minuteZero("0,30 6 * * *")}},
		{"a step from 0", wf("*/15 6 * * *"), 1, []string{minuteZero("*/15 6 * * *")}},
		{"four fields", wf("17 5 * *"), 1, []string{"t.yml: cron \"17 5 * *\" does not have five fields"}},
		{"two crons, one on the hour", []byte("on:\n  schedule:\n    - cron: \"17 5 * * *\"\n    - cron: \"0 21 * * 0\"\njobs: {}\n"), 2, []string{minuteZero("0 21 * * 0")}},
		{"no schedule", []byte("on: push\njobs: {}\n"), 0, nil},
		{"cron outside on.schedule", []byte("on: push\nx:\n  schedule:\n    - cron: \"0 6 * * *\"\njobs: {}\n"), 0, []string{
			"t.yml: 1 cron lines in the text, 0 parsed under on.schedule",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, n, err := scheduleProblems("t.yml", c.src)
			if err != nil {
				t.Fatal(err)
			}
			if n != c.crons {
				t.Errorf("judged %d crons, want %d", n, c.crons)
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("problems = %q\nwant       %q", got, c.want)
			}
		})
	}
}
