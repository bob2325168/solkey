package run

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"syscall"

	"github.com/kubetrail/solkey/pkg/flags"
	"github.com/mr-tron/base58"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stellar/go/exp/crypto/derivation"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/term"
)

func Gen(cmd *cobra.Command, args []string) error {
	_ = viper.BindPFlag(flags.UsePassphrase, cmd.Flags().Lookup(flags.UsePassphrase))
	_ = viper.BindPFlag(flags.SkipMnemonicValidation, cmd.Flags().Lookup(flags.SkipMnemonicValidation))
	_ = viper.BindPFlag(flags.InputHexSeed, cmd.Flags().Lookup(flags.InputHexSeed))
	_ = viper.BindPFlag(flags.DerivationPath, cmd.Flags().Lookup(flags.DerivationPath))

	derivationPath := viper.GetString(flags.DerivationPath)
	usePassphrase := viper.GetBool(flags.UsePassphrase)
	skipMnemonicValidation := viper.GetBool(flags.SkipMnemonicValidation)
	inputHexSeed := viper.GetBool(flags.InputHexSeed)

	derivationPath = strings.ReplaceAll(
		strings.ToLower(derivationPath), "h", "'")

	prompt, err := getPromptStatus()
	if err != nil {
		return fmt.Errorf("failed to get prompt status: %w", err)
	}

	var passphrase []byte
	var seed []byte

	if inputHexSeed && usePassphrase {
		return fmt.Errorf("cannot use passphrase when entering seed")
	}

	if inputHexSeed && skipMnemonicValidation {
		return fmt.Errorf("dont use --skip-mnemonic-validation when entering seed")
	}

	if !inputHexSeed {
		if prompt {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter mnemonic: "); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}

		inputReader := bufio.NewReader(cmd.InOrStdin())
		mnemonic, err := inputReader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read mnemonic from input: %w", err)
		}
		mnemonic = strings.Trim(mnemonic, "\n")

		if !skipMnemonicValidation && !bip39.IsMnemonicValid(mnemonic) {
			return fmt.Errorf("mnemonic is invalid or please use --skip-mnemonic-validation flag")
		}

		if usePassphrase {
			if prompt {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter secret passphrase: "); err != nil {
					return fmt.Errorf("failed to write to output: %w", err)
				}
			}

			passphrase, err = term.ReadPassword(syscall.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read secret passphrase from input: %w", err)
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout()); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}

			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter secret passphrase again: "); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}

			passphraseConfirm, err := term.ReadPassword(syscall.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read secret passphrase from input: %w", err)
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout()); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}

			if !bytes.Equal(passphrase, passphraseConfirm) {
				return fmt.Errorf("passphrases do not match")
			}
		}
		//seed = pbkdf2.Key([]byte(mnemonic), []byte("mnemonic"+string(passphrase)), 2048, 64, sha512.New)
		seed = bip39.NewSeed(mnemonic, string(passphrase))
	} else {
		if prompt {
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Enter seed in hex: "); err != nil {
				return fmt.Errorf("failed to write to output: %w", err)
			}
		}

		inputReader := bufio.NewReader(cmd.InOrStdin())
		hexSeed, err := inputReader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read mnemonic from input: %w", err)
		}
		hexSeed = strings.Trim(hexSeed, "\n")

		seed, err = hex.DecodeString(hexSeed)
		if err != nil {
			return fmt.Errorf("invalid seed: %w", err)
		}
	}

	prvKey, err := derivation.DeriveForPath(derivationPath, seed)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	pubKey, err := prvKey.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to derive pub key: %w", err)
	}

	outPrv := base58.Encode(bytes.Join([][]byte{prvKey.Key, pubKey}, nil))
	outPub := base58.Encode(pubKey)

	if prompt {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), "pub:", outPub); err != nil {
			return fmt.Errorf("failed to write key to output: %w", err)
		}

		if _, err := fmt.Fprintln(cmd.OutOrStdout(), "prv:", outPrv); err != nil {
			return fmt.Errorf("failed to write key to output: %w", err)
		}

		return nil
	}

	jb, err := json.Marshal(
		struct {
			Prv string `json:"prv,omitempty"`
			Pub string `json:"pub,omitempty"`
		}{
			Prv: outPrv,
			Pub: outPub,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to serialize output: %w", err)
	}

	if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(jb)); err != nil {
		return fmt.Errorf("failed to write key to output: %w", err)
	}

	return nil
}
