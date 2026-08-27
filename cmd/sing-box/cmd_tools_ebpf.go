//go:build with_ebpf && (linux || android)

package main

import (
	"fmt"
	"os"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/log"

	"github.com/spf13/cobra"
)

var (
	commandEBPFStatusMode      string
	commandEBPFStatusNetwork   []string
	commandEBPFStatusInterface string
	commandEBPFStatusJSON      bool
)

var commandEBPF = &cobra.Command{
	Use:   "ebpf",
	Short: "eBPF diagnostics",
}

var commandEBPFStatus = &cobra.Command{
	Use:   "status",
	Short: "Inspect eBPF inbound kernel support",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runEBPFStatus(); err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandEBPFStatus.Flags().StringVar(&commandEBPFStatusMode, "mode", "all", "Data path to inspect: all, local, or shared")
	commandEBPFStatus.Flags().StringSliceVar(&commandEBPFStatusNetwork, "network", []string{"tcp", "udp"}, "Protocols to inspect: tcp, udp, or tcp,udp")
	commandEBPFStatus.Flags().StringVar(&commandEBPFStatusInterface, "interface", "", "Configured shared interface")
	commandEBPFStatus.Flags().BoolVar(&commandEBPFStatusJSON, "json", false, "Write the report as JSON")
	commandEBPF.AddCommand(commandEBPFStatus)
	commandTools.AddCommand(commandEBPF)
}

func runEBPFStatus() error {
	report, err := commonEBPF.ProbeKernel(commonEBPF.KernelProbeOptions{
		Mode:          commonEBPF.KernelProbeMode(commandEBPFStatusMode),
		Network:       commandEBPFStatusNetwork,
		InterfaceName: commandEBPFStatusInterface,
	})
	if err != nil {
		return err
	}
	if commandEBPFStatusJSON {
		err = commonEBPF.WriteKernelProbeReportJSON(os.Stdout, report)
	} else {
		err = commonEBPF.WriteKernelProbeReport(os.Stdout, report)
	}
	if err != nil {
		return err
	}
	if failures := report.RequiredFailures(); failures > 0 {
		return fmt.Errorf("eBPF kernel capability probe found %d required failure(s)", failures)
	}
	return nil
}
