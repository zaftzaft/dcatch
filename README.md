dcatch
======
DHCP Request catcher


# Install
https://github.com/zaftzaft/dcatch/releases

# Usage
```console
$ sudo dcatch
192.168.0.30 Raspberry Pi Foundation[b8:27:eb:ff:ff:ff]@raspberry
```

# Build
## depends
- go
- [gopacket](https://github.com/google/gopacket)
- libpcap

## compile
```
$ go get github.com/google/gopacket
$ go get github.com/zaftzaft/dcatch
$ cd $GOPATH/src/github.com/zaftzaft/dcatch
$ go build
```

## single binary
```
$ go build --ldflags '-extldflags "-static"'
```
