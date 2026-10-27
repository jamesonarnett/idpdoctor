// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jamesonarnett/idpdoctor/internal/agent"
	"github.com/jamesonarnett/idpdoctor/internal/eval"
)

func newEvalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "eval",
		Short: "Benchmark harness: gen, run, judge, report (evals/)",
		Long: `The eval commands generate a labelled synthetic dataset, run the three arms
(rules, llm-tools-off, llm-tools-on), score answers with an LLM judge and
render the README numbers table. Model calls go through the same headless
claude -p path as --explain: subscription login only, never an API key.`,
	}
	cmd.AddCommand(newEvalGenCmd(), newEvalRunCmd(), newEvalJudgeCmd(), newEvalReportCmd())
	return cmd
}

func newEvalGenCmd() *cobra.Command {
	var o eval.GenOptions
	cmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate N cases per class plus healthy controls and posture fixtures",
		RunE: func(cmd *cobra.Command, args []string) error {
			cases, err := eval.Gen(o)
			if err != nil {
				return err
			}
			faults, controls, posture := 0, 0, 0
			for _, c := range cases {
				switch {
				case c.IsPosture():
					posture++
				case c.IsControl():
					controls++
				default:
					faults++
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %d cases to %s (%d fault, %d control, %d posture; seed %d)\n", len(cases), o.Out, faults, controls, posture, o.Seed)
			return nil
		},
	}
	cmd.Flags().Uint64Var(&o.Seed, "seed", 42, "seed; the same seed reproduces the same dataset")
	cmd.Flags().IntVar(&o.PerClass, "per-class", 10, "fault cases per catalog class that has a mutator")
	cmd.Flags().IntVar(&o.Controls, "controls", 30, "healthy controls (a third with a misleading symptom)")
	cmd.Flags().IntVar(&o.PerPosture, "per-posture", 0, "validating artifacts per posture code (default per-class/2)")
	cmd.Flags().StringVar(&o.Templates, "templates", "evals/symptom_templates", "directory of *.json symptom templates (code -> strings)")
	cmd.Flags().StringVar(&o.Out, "out", "evals/data/v1", "dataset directory")
	return cmd
}

func newEvalRunCmd() *cobra.Command {
	var o eval.RunOptions
	var arms []string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run one or more arms over a dataset; resumable, cached by case hash",
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.Results == "" {
				o.Results = filepath.Join("evals", "results", filepath.Base(o.Dataset))
			}
			if o.ServerBin == "" {
				exe, err := os.Executable()
				if err != nil {
					return err
				}
				o.ServerBin = exe
			}
			eval.Version = version
			o.Out = cmd.ErrOrStderr()
			totalCalls := 0
			for _, arm := range arms {
				if arm != eval.ArmRules && arm != eval.ArmToolsOff && arm != eval.ArmToolsOn {
					return fmt.Errorf("unknown arm %q (rules, llm-tools-off, llm-tools-on)", arm)
				}
				ao := o
				ao.Arm = arm
				if o.MaxCalls > 0 {
					ao.MaxCalls = o.MaxCalls - totalCalls
					if ao.MaxCalls <= 0 && arm != eval.ArmRules {
						return fmt.Errorf("%w (%d) before arm %s", eval.ErrMaxCalls, o.MaxCalls, arm)
					}
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "== arm %s (model %s, concurrency %d) ==\n", arm, o.Model, o.Concurrency)
				results, calls, err := eval.Run(cmd.Context(), ao)
				totalCalls += calls
				summarise(cmd, arm, results, calls)
				if err != nil {
					return fmt.Errorf("arm %s stopped: %w (%d real calls this invocation)", arm, err, totalCalls)
				}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "real claude calls this invocation: %d; results under %s\n", totalCalls, o.Results)
			return nil
		},
	}
	cmd.Flags().StringVar(&o.Dataset, "dataset", "evals/data/v1", "dataset directory from eval gen")
	cmd.Flags().StringSliceVar(&arms, "arm", []string{eval.ArmRules}, "arms to run: rules, llm-tools-off, llm-tools-on (repeatable or comma-separated)")
	cmd.Flags().StringVar(&o.Model, "model", agent.DefaultModel, "diagnoser model alias for the LLM arms")
	cmd.Flags().StringVar(&o.Results, "results", "", "results root (default evals/results/<dataset name>)")
	cmd.Flags().IntVar(&o.Concurrency, "concurrency", 1, "parallel cases (max 2)")
	cmd.Flags().IntVar(&o.MaxCalls, "max-calls", 0, "hard cap on real claude calls in this invocation (0 = none)")
	cmd.Flags().StringSliceVar(&o.Only, "only", nil, "restrict to these case IDs")
	cmd.Flags().BoolP("resume", "r", true, "reuse cached results (always on; present for the BUILD_PLAN spelling)")
	return cmd
}

func summarise(cmd *cobra.Command, arm string, results []*eval.CaseResult, calls int) {
	correct, errs := 0, 0
	for _, r := range results {
		if r.Error != "" {
			errs++
		} else if r.Correct() {
			correct++
		}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s: %d cases, %d correct, %d errors, %d real calls\n", arm, len(results), correct, errs, calls)
}

func newEvalJudgeCmd() *cobra.Command {
	var o eval.JudgeOptions
	var labels string
	cmd := &cobra.Command{
		Use:   "judge",
		Short: "Score cached results with an LLM judge (opus by default) and report kappa against hand labels",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(o.Arms) == 0 {
				entries, err := os.ReadDir(o.Results)
				if err != nil {
					return err
				}
				for _, e := range entries {
					if e.IsDir() && !strings.HasPrefix(e.Name(), "judge-") {
						o.Arms = append(o.Arms, e.Name())
					}
				}
			}
			o.Out = cmd.ErrOrStderr()
			verdicts, calls, err := eval.Judge(cmd.Context(), o)
			fmt.Fprintf(cmd.OutOrStdout(), "judged %d result(s) with %s (%d real calls this invocation)\n", len(verdicts), o.Model, calls)
			if labels != "" {
				if hl, lerr := eval.LoadHandLabels(labels); lerr == nil && len(hl) > 0 {
					a := eval.Agree(verdicts, hl)
					fmt.Fprintf(cmd.OutOrStdout(), "agreement on %d pairs: kappa(evidence)=%.2f (%.0f%% agree), weighted kappa(fix)=%.2f (%.0f%% agree), placeholder=%v\n",
						a.Pairs, a.KappaEvidence, 100*a.AgreeEvidence, a.WeightedKappaFix, 100*a.AgreeFix, a.Placeholder)
				} else if lerr != nil && !errors.Is(lerr, os.ErrNotExist) {
					return lerr
				}
			}
			return err
		},
	}
	cmd.Flags().StringVar(&o.Results, "results", "evals/results/v1", "results root from eval run")
	cmd.Flags().StringSliceVar(&o.Arms, "arm", nil, "arm result dirs to judge (default: all under --results)")
	cmd.Flags().StringVar(&o.Model, "model", agent.JudgeModel, "judge model alias (keep it different from the diagnoser)")
	cmd.Flags().StringVar(&o.Rubric, "rubric", "evals/rubric.md", "rubric prompt")
	cmd.Flags().StringVar(&labels, "labels", "evals/labels/hand_labels.csv", "hand labels CSV for kappa")
	cmd.Flags().IntVar(&o.Limit, "limit", 0, "judge at most this many new results (0 = all)")
	cmd.Flags().StringSliceVar(&o.Only, "only", nil, "restrict to these case IDs")
	cmd.Flags().IntVar(&o.Concurrency, "concurrency", 1, "parallel calls (max 2)")
	cmd.Flags().IntVar(&o.MaxCalls, "max-calls", 0, "hard cap on real claude calls (0 = none)")
	return cmd
}

func newEvalReportCmd() *cobra.Command {
	var o eval.ReportOptions
	var out string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render the README numbers table and per-class confusion matrices from cached results",
		RunE: func(cmd *cobra.Command, args []string) error {
			rep, err := eval.Build(o)
			if err != nil {
				return err
			}
			md := rep.Markdown()
			if out != "" {
				if err := os.WriteFile(out, []byte(md), 0o644); err != nil {
					return err
				}
				if err := writeJSONFile(filepath.Join(filepath.Dir(out), "summary.json"), rep); err != nil {
					return err
				}
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), md)
			return err
		},
	}
	cmd.Flags().StringVar(&o.Results, "results", "evals/results/v1", "results root")
	cmd.Flags().StringVar(&o.Dataset, "dataset", "evals/data/v1", "dataset directory (for the case count)")
	cmd.Flags().StringVar(&o.JudgeModel, "judge-model", agent.JudgeModel, "judge model whose verdicts to use")
	cmd.Flags().StringVar(&o.Labels, "labels", "evals/labels/hand_labels.csv", "hand labels CSV for the kappa line")
	cmd.Flags().StringVar(&out, "out", "", "also write the markdown here (and summary.json beside it)")
	return cmd
}

func writeJSONFile(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeJSON(f, v)
}
