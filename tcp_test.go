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
			prog.DecodeToReader(os.Stdout)
			t.Fatalf("%s: %v", testCase.name, err)
		}

		if result.ReturnValue != testCase.expected {
			prog.DecodeToReader(os.Stdout)
			t.Fatalf("%s: expected '%d', got '%d'", testCase.name, testCase.expected, result.ReturnValue)
		}
	}
}

// This unit test tests all avaiable fields in a TCP packet
func Test_genericTCPField(t *testing.T) {
	policy := Policy{
		Rules: []Rule{
			{
				Match: &TCPFieldMatch{
					Field: TCPSourcePort,
					Op:    OpEquals,
					Value: 123,
				},
				Action: &testReturn{
					value: 1,
				},
			},
			{
				Match: &TCPFieldMatch{
					Field: TCPDestinationPort,
					Op:    OpEquals,
					Value: 123,
				},
				Action: &testReturn{
					value: 2,
				},
			},
			{
				Match: &TCPFieldMatch{
					Field: TCPSequence,
					Op:    OpEquals,
					Value: 123,
				},
				Action: &testReturn{
					value: 3,
				},
			},
			{
				Match: &TCPFieldMatch{
					Field: TCPDataOffset,
					Op:    OpEquals,
					Value: 2,
				},
				Action: &testReturn{
					value: 4,
				},
			},
			{
				Match: &TCPFieldMatch{
					Field: TCPFlagNS,
					Op:    OpEquals,
					Value: 1,
				},
				Action: &testReturn{
					value: 5,
				},
			},
			{
				Match: &TCPFieldMatch{
					Field: TCPFlagCWR,
					Op:    OpEquals,
					Value: 1,
				},
				Action: &testReturn{
					value: 6,
				},
			},
			{
				Match: &TCPFieldMatch{
					Field: TCPFlagECE,
					Op:    OpEquals,
					Value: 1,
				},
				Action: &testReturn{
					value: 7,
				},
			},
			{
				Match: &TCPFieldMatch{
					Field: TCPFlagURG,
					Op:    OpEquals,
					Value: 1,
				},
				Action: &testReturn{
					value: 8,
				},
			},
			{
				Match: &TCPFieldMatch{
					Field: TCPFlagACK,
					Op:    OpEquals,
					Value: 1,
				},
				Action: &testReturn{
					value: 9,
				},
			},
			{
				Match: &TCPFieldMatch{
					Field: TCPFlagPSH,
					Op:    OpEquals,
					Value: 1,
				},
				Action: &testReturn{
					value: 10,
				},
			},
			{
				Match: &TCPFieldMatch{
					Field: TCPFlagRST,
					Op:    OpEquals,
					Value: 1,
				},
				Action: &testReturn{
					value: 11,
				},
			},
			{
				Match: &TCPFieldMatch{
					Field: TCPFlagSYN,
					Op:    OpEquals,
					Value: 1,
				},
				Action: &testReturn{
					value: 12,
				},
			},
			{
				Match: &TCPFieldMatch{
					Field: TCPFlagFIN,
					Op:    OpEquals,
					Value: 1,
				},
				Action: &testReturn{
					value: 13,
				},
			},
			{
				Match: &TCPFieldMatch{
					Field: TCPWindowSize,
					Op:    OpEquals,
					Value: 123,
				},
				Action: &testReturn{
					value: 14,
				},
			},
			{
				Match: &TCPFieldMatch{
					Field: TCPChecksum,
					Op:    OpEquals,
					Value: 123,
				},
				Action: &testReturn{
					value: 15,
				},
			},
			{
				Match: &TCPFieldMatch{
					Field: TCPUrgentPointer,
					Op:    OpEquals,
					Value: 123,
				},
				Action: &testReturn{
					value: 16,
				},
			},
		},
		DefaultAction: &testReturn{
			value: 0,
		},
	}

	inst, err := policy.Compile()
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

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		DstMAC:       net.HardwareAddr{0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		SrcIP:    net.IPv4(11, 12, 13, 14),
		DstIP:    net.IPv4(21, 22, 23, 24),
		Protocol: layers.IPProtocolTCP,
	}
	payload := gopacket.Payload{0xDE, 0xAD, 0xBE, 0xEF}

	type testcase struct {
		name     string
		layers   []gopacket.SerializableLayer
		expected int32
	}
	cases := []testcase{
		{
			name: "No match",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{},
				payload,
			},
			expected: 0,
		},
		{
			name: "SRC Match",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					SrcPort: 123,
				},
				payload,
			},
			expected: 1,
		},
		{
			name: "DST Match",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					DstPort: 123,
				},
				payload,
			},
			expected: 2,
		},
		{
			name: "Sequence Match",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					Seq: 123,
				},
				payload,
			},
			expected: 3,
		},
		{
			name: "Data offset",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					DataOffset: 2,
				},
				payload,
			},
			expected: 4,
		},
		{
			name: "Flag NS",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					NS: true,
				},
				payload,
			},
			expected: 5,
		},
		{
			name: "Flag CWR",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					CWR: true,
				},
				payload,
			},
			expected: 6,
		},
		{
			name: "Flag ECE",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					ECE: true,
				},
				payload,
			},
			expected: 7,
		},
		{
			name: "Flag URG",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					URG: true,
				},
				payload,
			},
			expected: 8,
		},
		{
			name: "Flag ACK",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					ACK: true,
				},
				payload,
			},
			expected: 9,
		},
		{
			name: "Flag PSH",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					PSH: true,
				},
				payload,
			},
			expected: 10,
		},
		{
			name: "Flag RST",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					RST: true,
				},
				payload,
			},
			expected: 11,
		},
		{
			name: "Flag SYN",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					SYN: true,
				},
				payload,
			},
			expected: 12,
		},
		{
			name: "Flag FIN",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					FIN: true,
				},
				payload,
			},
			expected: 13,
		},
		{
			name: "Window",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					Window: 123,
				},
				payload,
			},
			expected: 14,
		},
		{
			name: "Checksum",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					Checksum: 123,
				},
				payload,
			},
			expected: 15,
		},
		{
			name: "Urgent ptr",
			layers: []gopacket.SerializableLayer{
				eth,
				ip,
				&layers.TCP{
					Urgent: 123,
				},
				payload,
			},
			expected: 16,
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
