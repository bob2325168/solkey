package run

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/kubetrail/solkey/pkg/flags"
	"github.com/mr-tron/base58"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func Hash(cmd *cobra.Command, args []string) error {
	_ = viper.BindPFlag(flags.Filename, cmd.Flags().Lookup(flags.Filename))
	fileName := viper.GetString(flags.Filename)

	prompt, err := getPromptStatus()
	if err != nil {
		return fmt.Errorf("failed to get prompt status: %w", err)
	}

	var b []byte
	if len(fileName) > 0 {
		if fileName == "-" {
			if b, err = io.ReadAll(cmd.InOrStdin()); err != nil {
				return fmt.Errorf("failed to read stdin input: %w", err)
			}
		} else {
			if b, err = os.ReadFile(fileName); err != nil {
				return fmt.Errorf("failed to read input file %s: %w", fileName, err)
			}
		}
	} else {
		if len(args) == 0 {
			return fmt.Errorf("no input file or args, pl. provide input to sign")
		}
		b = []byte(strings.Join(args, " "))
	}

	hash := crypto.Keccak256(b)
	hashB58 := base58.Encode(hash)

	if prompt {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), "hash: ", hashB58); err != nil {
			return fmt.Errorf("failed to write to output: %w", err)
		}

		return nil
	}

	jb, err := json.Marshal(
		struct {
			Hash string `json:"hash,omitempty"`
		}{
			Hash: hashB58,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to serialize output: %w", err)
	}

	if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(jb)); err != nil {
		return fmt.Errorf("failed to write to output: %w", err)
	}

	return nil
}
