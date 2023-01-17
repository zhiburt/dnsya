# dnsya

`dnsya` is a libpcap application (like tcpdump) that displays various tables of DNS traffic on your network.

## Installation

```
git clone https://github.com/zhiburt/dnsya
cd dnsya
cargo install --path .
```

## Usage

```bash
sudo dnsya -f r -o name wlan0
```
___________

Inspired by [`dnstop`](https://github.com/measurement-factory/dnstop)