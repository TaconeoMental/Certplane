package main

import (
	"context"
	"fmt"

	"github.com/TaconeoMental/certplane/internal/broker/policy"
	"github.com/spf13/cobra"
)

func newPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Policy utilities",
	}
	cmd.AddCommand(newPolicyValidateCommand())
	return cmd
}

func newPolicyValidateCommand() *cobra.Command {
	var policyPath string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate and compile a broker policy file",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicyValidate(cmd.Context(), policyPath, cmd)
		},
	}
	cmd.Flags().StringVar(&policyPath, "policy", "", "broker policy YAML file")
	return cmd
}

func runPolicyValidate(_ context.Context, policyPath string, cmd *cobra.Command) error {
	if policyPath == "" {
		return fmt.Errorf("--policy is required")
	}

	compiled, err := policy.Load(policyPath)
	if err != nil {
		return err
	}

	fmt.Fprintf(
		cmd.OutOrStdout(),
		"policy ok: hash=%s profiles=%d identities=%d\n",
		compiled.Hash,
		len(compiled.Profiles),
		len(compiled.HostsByIdentity),
	)
	return nil
}
