# ZAP Ascan Monitor

Simple monitoring of ongoing active scan in ZAP. Implemented in Rust.

## Build

```shell
git clone
cd zam
cargo build --release
./target/release/zam -h
```

## Usage

Firstly, export ZAP API key.

```shell
export ZAP_KEY=*****
```

Then call zam, use `-a` to point ZAP API placement in format `<ip:port>`, 
use `-i` to point id of active scan you interested in, use `-m` to switch to monitor mode.

```shell
zam -a 127.0.0.1:8000 -i 0 -m
```
