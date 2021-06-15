package main

import (
	"fmt"
	"os"
	"os/signal"

	// github.com/davecgh/go-spew/spew

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/ebpf"
)

func main() {
	policy := Policy{
		Rules: []Rule{
			// {
			// 	Name: "localhost-01<->02",
			// 	Match: &OrMatch{
			// 		SubMatch: []Match{
			// 			&AndMatch{
			// 				SubMatch: []Match{
			// 					&IPv4FieldMatch{
			// 						Field: IPv4SourceAddress,
			// 						Op:    OpEquals,
			// 						Value: 0x0100007F,
			// 					},
			// 					&IPv4FieldMatch{
			// 						Field: IPv4DestinationAddress,
			// 						Op:    OpEquals,
			// 						Value: 0x0200007F,
			// 					},
			// 				},
			// 			},
			// 			&AndMatch{
			// 				SubMatch: []Match{
			// 					&IPv4FieldMatch{
			// 						Field: IPv4SourceAddress,
			// 						Op:    OpEquals,
			// 						Value: 0x0200007F,
			// 					},
			// 					&IPv4FieldMatch{
			// 						Field: IPv4DestinationAddress,
			// 						Op:    OpEquals,
			// 						Value: 0x0100007F,
			// 					},
			// 				},
			// 			},
			// 		},
			// 	},
			// 	Action: &Pass{},
			// },
			{
				Name: "test",
				Match: &OrMatch{
					SubMatch: []Match{
						&TCPFieldMatch{
							Field: TCPSourcePort,
							Op:    OpEquals,
							Value: int(ebpf.HtonU16(80)),
						},
						&TCPFieldMatch{
							Field: TCPDestinationPort,
							Op:    OpEquals,
							Value: int(ebpf.HtonU16(80)),
						},
					},
				},
				Action: &Pass{},
			},
		},
		DefaultAction: &Drop{},
	}

	asm, err := policy.Assemble()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error assembly: ", err.Error())
		os.Exit(1)
	}

	fmt.Print(asm)

	inst, err := policy.Compile()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error compile: ", err.Error())
		os.Exit(1)
	}

	rawInst, err := ebpf.Encode(inst)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error encode: ", err.Error())
		os.Exit(1)
	}

	prog := &gobpfld.BPFProgram{
		Name:         gobpfld.MustNewObjName("firewall"),
		Instructions: rawInst,
		License:      "GPL",
	}

	err = prog.DecodeToReader(os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error decode: ", err.Error())
		os.Exit(1)
	}

	log, err := prog.Load(gobpfld.BPFProgramLoadSettings{
		ProgramType:      bpftypes.BPF_PROG_TYPE_XDP,
		VerifierLogLevel: bpftypes.BPFLogLevelVerbose,
	})
	fmt.Printf("\nVerifier log:\n%s\n", log)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error load: ", err.Error())
		os.Exit(1)
	}

	err = prog.XDPLinkAttach(gobpfld.BPFProgramXDPLinkAttachSettings{
		InterfaceName: "lo",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error attach: ", err.Error())
		os.Exit(1)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	err = prog.XDPLinkDetach(gobpfld.BPFProgramXDPLinkDetachSettings{
		All: true,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error detach: ", err.Error())
		os.Exit(1)
	}
}
