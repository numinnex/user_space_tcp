#!/bin/bash

# adjust this variable to fit your path, CARGO_OUTPUT_DIR by default should point to target
# but on my current setup for some reason doesn't...
CARGO_OUTPUT_DIR="$HOME/projects/user_space_tcp/target"
cargo b -r
sudo setcap cap_net_admin=eip $CARGO_OUTPUT_DIR/release/user_space_tcp
$CARGO_OUTPUT_DIR/release/user_space_tcp &
pid=$!
sudo ip addr add 192.168.0.69/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid
