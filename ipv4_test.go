package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func Test_getIPv4Header(t *testing.T) {
	asm := getIPv4Header()

	inst, err := ebpf.AssemblyToInstructions("generated-assembly", strings.NewReader(strings.Join(asm, "\n")))
	if err != nil {
		t.Fatal(err)
	}

	rawInst, err := ebpf.Encode(inst)
	if err != nil {
		t.Fatal(err)
	}

	prog := gobpfld.BPFProgram{
		Name:         gobpfld.MustNewObjName("ipv4_test"),
		License:      "GPL",
		Instructions: rawInst,
	}

	log, err := prog.Load(gobpfld.BPFProgramLoadSettings{
		ProgramType:      bpftypes.BPF_PROG_TYPE_XDP,
		VerifierLogLevel: bpftypes.BPFLogLevelVerbose,
		VerifierLogSize:  1024 * 1024 * 2,
	})
	if err != nil {
		fmt.Println(log)
		t.Fatal(err)
	}

	type testcase struct {
		name     string
		layers   []gopacket.SerializableLayer
		expected int32
	}
	cases := []testcase{
		{
			name: "Eth -> IPv4 happy path",
			layers: []gopacket.SerializableLayer{
				&layers.Ethernet{
					SrcMAC:       net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
					DstMAC:       net.HardwareAddr{0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C},
					EthernetType: layers.EthernetTypeIPv4,
				},
				&layers.IPv4{
					Version:  4,
					IHL:      5,
					SrcIP:    net.IPv4(11, 12, 13, 14),
					DstIP:    net.IPv4(21, 22, 23, 24),
					Protocol: layers.IPProtocolTCP,
				},
				gopacket.Payload{0xDE, 0xAD, 0xBE, 0xEF},
			},
			expected: 14,
		},
		{
			name: "Eth -> 802.1Q -> IPv4 Happy path",
			layers: []gopacket.SerializableLayer{
				&layers.Ethernet{
					SrcMAC:       net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
					DstMAC:       net.HardwareAddr{0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C},
					EthernetType: layers.EthernetTypeDot1Q,
				},
				&layers.Dot1Q{
					Priority:       123,
					DropEligible:   true,
					VLANIdentifier: 456,
					Type:           layers.EthernetTypeIPv4,
				},
				&layers.IPv4{
					Version:  4,
					IHL:      5,
					SrcIP:    net.IPv4(11, 12, 13, 14),
					DstIP:    net.IPv4(21, 22, 23, 24),
					Protocol: layers.IPProtocolTCP,
				},
				gopacket.Payload{0xDE, 0xAD, 0xBE, 0xEF},
			},
			expected: 18,
		},
		{
			name: "Eth -> (missing) 802.1Q",
			layers: []gopacket.SerializableLayer{
				&layers.Ethernet{
					SrcMAC:       net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
					DstMAC:       net.HardwareAddr{0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C},
					EthernetType: layers.EthernetTypeDot1Q,
				},
			},
			expected: -1,
		},
		{
			name: "Eth -> 802.1Q -> not-IPv4",
			layers: []gopacket.SerializableLayer{
				&layers.Ethernet{
					SrcMAC:       net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
					DstMAC:       net.HardwareAddr{0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C},
					EthernetType: layers.EthernetTypeDot1Q,
				},
				&layers.Dot1Q{
					Priority:       123,
					DropEligible:   true,
					VLANIdentifier: 456,
					Type:           layers.EthernetTypeIPv6,
				},
				gopacket.Payload{0xDE, 0xAD, 0xBE, 0xEF},
			},
			expected: -1,
		},
	}

	for _, testCase := range cases {
		buf := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{},
			testCase.layers...,
		)
		if err != nil {
			t.Fatalf("%s: %v", testCase.name, err)
		}

		result, err := prog.XDPTestProgram(gobpfld.TestXDPProgSettings{
			Data: buf.Bytes(),
		})
		if err != nil {
			prog.DecodeToReader(os.Stdout)
			t.Fatalf("%s: %v", testCase.name, err)
		}

		if result.ReturnValue != testCase.expected {
			prog.DecodeToReader(os.Stdout)
			t.Fatalf("%s: expected '%d', got '%d'", testCase.name, testCase.expected, result.ReturnValue)
		}
	}
}
