# example: ssh shell

Run an SSH server on the tailnet that serves real `exec` and `shell` sessions, authenticating
clients against an OpenSSH `authorized_keys` file.

Unlike [ssh_peer_lookup](../ssh_peer_lookup), which serves a TUI and accepts anyone the packet
filter lets through, this example checks public keys: `none` and `password` authentication are
refused, and only `publickey` is advertised. Tailnet policy rules still apply underneath — a peer
that policy forbids from reaching the listen port never gets as far as authenticating. The `ssh`
policy file block is still not consulted.

The server key is randomized on each start, so you will likely want to connect using
`-o StrictHostKeyChecking=no`.

Whether any of this belongs upstream is under discussion in
[tailscale/tailscale-rs#285](https://github.com/tailscale/tailscale-rs/issues/285).

## Sessions have no pty

`pty-req` is refused, so every session is pipe-backed:

- `exec` channels (`ssh host -- some command`) work normally; they never wanted a pty.
- `shell` channels work, but without terminal emulation: no line editing, no `^C` delivery, no
  resize handling. `ssh -T` is the honest way to open one.

This is deliberate. Allocating a pty on Windows means ConPTY, which does not exist before Windows
10 version 1809, and this tree targets Windows 7 (see [docs/win7.md](../../docs/win7.md)). Serving
pipes on every platform beats serving a pty everywhere except the platform we care about.

## Example usage

```shell
$ cargo run --example ssh_shell --features ssh -- \
      -k $MY_AUTH_KEY -c $MY_CONFIG_FILE -A ~/.ssh/authorized_keys
...
INFO ssh_shell: loaded authorized keys keys=1 path=/home/you/.ssh/authorized_keys
INFO tailscale::ssh: ssh server listening listen_addr=$TAILNET_IP:22
...

# in another terminal -- run a single command:
$ ssh $TAILNET_IP -o StrictHostKeyChecking=no -- uname -a

# ...or open an interactive (pipe-backed) shell:
$ ssh $TAILNET_IP -o StrictHostKeyChecking=no -T
```

The listen port defaults to 22. On unix, binding it needs privileges the example is unlikely to
have; pass `--listen-port` to pick an unprivileged one.
