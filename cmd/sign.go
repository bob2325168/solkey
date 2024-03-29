/*
Copyright © 2022 kubetrail.io authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"github.com/kubetrail/solkey/pkg/flags"
	"github.com/kubetrail/solkey/pkg/run"
	"github.com/spf13/cobra"
)

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign input",
	Long:  `This command signs input using private key`,
	RunE:  run.Sign,
}

func init() {
	rootCmd.AddCommand(signCmd)
	f := signCmd.Flags()

	f.String(flags.Filename, "", "Input file to sign")
}
