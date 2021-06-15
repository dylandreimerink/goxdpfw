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

func Test_getTCPHeader(t *testing.T) {
	asm := append(getTCPHeader(), getIPv4Header()...)

	inst, err := ebpf.AssemblyToInstructions("generated-assembly", strings.NewReader(strings.Join(asm, "\n")))
	if err != nil {
		t.Fatal(err)
	}

	rawInst, err := ebpf.Encode(inst)
	if err != nil {
		t.Fatal(err)
	}

	prog := gobpfld.BPFProgram{
		Name:         gobpfld.MustNewObjName("tcp_test"),
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

	prog.DecodeToReader(os.Stdout)

	type testcase struct {
		name     string
		layers   []gopacket.SerializableLayer
		expected int32
	}
	cases := []testcase{
		{
			name: "Eth -> IPv4 -> TCP happy path",
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
				&layers.TCP{
					SrcPort: 123,
					DstPort: 345,
				},
				gopacket.Payload{0xDE, 0xAD, 0xBE, 0xEF},
			},
			expected: 34,
		},
		{
			name: "Eth -> 802.1Q -> IPv4 -> TCP Happy path",
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
				&layers.TCP{
					SrcPort: 123,
					DstPort: 345,
				},
				gopacket.Payload{0xDE, 0xAD, 0xBE, 0xEF},
			},
			expected: 38,
		},
		{
			name: "Eth -> 802.1Q -> IPv4 -> no-tcp",
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
					Protocol: layers.IPProtocolICMPv4,
				},
				gopacket.Payload{0xDE, 0xAD, 0xBE, 0xEF},
			},
			expected: -1,
		},
		{
			name: "Eth -> no-ipv4",
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
		{
			name: "Eth -> IPv4 (+options) -> TCP",
			layers: []gopacket.SerializableLayer{
				&layers.Ethernet{
					SrcMAC:       net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
					DstMAC:       net.HardwareAddr{0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C},
					EthernetType: layers.EthernetTypeIPv4,
				},
				&layers.IPv4{
					Version:  4,
					IHL:      7,
					SrcIP:    net.IPv4(11, 12, 13, 14),
					DstIP:    net.IPv4(21, 22, 23, 24),
					Protocol: layers.IPProtocolTCP,
					Options: []layers.IPv4Option{
						{OptionType: 3, OptionLength: 8, OptionData: []byte{
							0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
						}},
					},
				},
				&layers.TCP{
					SrcPort: 123,
					DstPort: 345,
				},
				gopacket.Payload{0xDE, 0xAD, 0xBE, 0xEF},
			},
			expected: 42,
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
			t.Fatalf("%s: %v", testCase.name, err)
		}

		if result.ReturnValue != testCase.expected {
			t.Fatalf("%s: expected '%d', got '%d'", testCase.name, testCase.expected, result.ReturnValue)
		}
	}
}
