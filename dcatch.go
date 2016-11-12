package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/macs"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
)

var version = "0.0.2"

func main() {
	var device string
	flag.StringVar(&device, "i", "any", "interface name")

	var filename string
	flag.StringVar(&filename, "r", "", "pcap file")

	var showVersion bool
	flag.BoolVar(&showVersion, "v", false, "show version")
	flag.BoolVar(&showVersion, "version", false, "show version")

	flag.Parse()

	if showVersion {
		fmt.Println("dcatch version ", version)
		return
	}

	var handle *pcap.Handle
	var err error
	if filename != "" {
		handle, err = pcap.OpenOffline(filename)
		if err != nil {
			log.Fatal("[Error] pcap OpenOffline err", err)
		}
	} else {
		handle, err = pcap.OpenLive(device, 65536, true, time.Second)
		if err != nil {
			log.Fatal("pcap openlive err:", err)
		}
	}

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		var (
			msgtype  layers.DHCPMsgType
			hostname string
			request  net.IP
		)

		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcpLayer == nil {
			continue
		}

		dhcp := dhcpLayer.(*layers.DHCPv4)

		for _, option := range dhcp.Options {
			switch option.Type {
			case 0x35:
				msgtype = layers.DHCPMsgType(option.Data[0])
			case 0xc:
				hostname = string(option.Data)
			case 0x32:
				request = net.IP(option.Data)
			}
		}

		if msgtype != layers.DHCPMsgTypeRequest {
			continue
		}

		b := []byte(dhcp.ClientHWAddr[0:3])
		oui := [3]byte{b[0], b[1], b[2]}

		fmt.Printf("%s %s[%s]@%s\n", request, macs.ValidMACPrefixMap[oui], dhcp.ClientHWAddr, hostname)

	}
}
