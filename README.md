# sipxtract

*sipxtract* is a small tool to extract SIP telephony calls from a PCAP source.
It's pretty fast and scans through huge (>50 GB) PCAP dump file in just a few seconds.

After extraction you can proceed with your normal workflow and load your files in  [wireshark](https://www.wireshark.org/), [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) or [sipgrep](https://github.com/sipcapture/sipgrep).


## Installation

### Quick install (recommended)

```sh
curl -fsSL https://raw.githubusercontent.com/maurice2k/sipxtract/main/install.sh | sh
```

Installs to `/usr/local/bin` by default. To install elsewhere:

```sh
INSTALL_DIR=~/.local/bin curl -fsSL https://raw.githubusercontent.com/maurice2k/sipxtract/main/install.sh | sh
```

### From source (go install)

```sh
go install github.com/maurice2k/sipxtract@latest
```

## Sample usage
```
$ sipxtract -v --in huge-50gb-sip-traffic.pcap 7aed7162-d029-49b2-868a-84e38ff56ea1 010fe5bf-3cd6-44ab-a1c7-691fe85cfa2d >relevant-calls.pcap
```
This would extract SIP and RTP packets for SIP calls matching the given Call-Ids `7aed7162-d029-49b2-868a-84e38ff56ea1` and `010fe5bf-3cd6-44ab-a1c7-691fe85cfa2d` into `relevant-calls.pcap` file.
By default extraction will be stopped as soon as the given SIP calls are completed protocol-wise unless you specify `--full-scan`. This will scan through all packets available regardless of the state of the corresponding SIP call.

## Available command line options
```
Usage:
  sipxtract [OPTIONS] [Call-Id...]

Application Options:
      --in=           Source PCAP file (default: STDIN)
      --out=          Output PCAP file (default: STDOUT)
  -p, --port=         SIP port filter (multiple ports allowed) (default: 5060)
      --skip-rtp      Skip RTP media packets
      --rtp-tail=     Seconds of RTP to capture after call ends (default: 10)
      --rtp-filter-ip Filter RTP by IPs from SDP connection lines
      --full-scan     Do a full scan even though given calls seem to be finished
  -v, --verbose       Show verbose information (use -vv to also dump raw SIP messages)
      --version       Show sipxtract version

Help Options:
  -h, --help       Show this help message

Arguments:
  Call-Id:         SIP Call-Id header value
```

## License

*sipxtract* is available under the MIT [license](LICENSE).
