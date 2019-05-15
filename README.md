# Linux client/server implementation of a custom 4over6 protocol

This repo includes client and server implementation of a custom 4over6 protocol.

## How to build

You need to install libuv (`libuv1-dev` for Ubuntu, `libuv` for Arch Linux)

```shell
make all
```

This produces `server` and `client` in the current directory.

## How to use

### Server side

Run `sudo ./server`:

```shell
sudo ./server
```

It will create a TUN device called `4over6server` and assign an IP to it (don't blame me for the IP). It will now accept client connections to localhost:5678

### Client side

Run `sudo ./client -s [server_addr]`

```shell
sudo ./client # default server addr
sudo ./client -s :: # server on localhost
```

It will create a netns called `4over6` and create a TUN device called `4over6` in the newly created netns. You can type `sudo ip netns exec 4over6 bash` to enter the netns. If you don't want a netns, you can set `--no-netns` to disable it.

More command line arguments can be found by `./client -h`.

If you have everything configured correctly, you can now ping the server address:

```shell
$ ping 13.8.0.1
PING 13.8.0.1 (13.8.0.1) 56(84) bytes of data.
64 bytes from 13.8.0.1: icmp_seq=1 ttl=64 time=0.376 ms
64 bytes from 13.8.0.1: icmp_seq=2 ttl=64 time=0.325 ms
^C
--- 13.8.0.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 15ms
rtt min/avg/max/mdev = 0.325/0.350/0.376/0.031 ms
```

(Don't blame me for the IP, again)

If you correctly setup NAT, you should now be able to visit the Internet in the netns.

