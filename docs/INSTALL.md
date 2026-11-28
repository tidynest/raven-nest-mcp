# Installing and running

**In short:**
Raven Nest is one binary, `raven-server`, that speaks MCP over stdio. It
***opens no network port***. An MCP client starts it as a child process and
talks to it over stdin and stdout.

There are four ways to get it. The container is ***the only one that also
brings the scanners***.

| Method | Brings the scanners | Platform |
|--------|---------------------|----------|
| [Container image](#container-image) | yes, all 22 | x86_64 Linux image |
| [Prebuilt binary](#prebuilt-binary) | no | x86_64 Linux with glibc |
| [Build from source](#build-from-source) | no | Linux, Rust 1.93 or newer |
| [Arch Linux PKGBUILD](#arch-linux-pkgbuild) | no, listed as optional dependencies | x86_64 Arch |

Nothing else is built or tested.

The code uses Unix file modes and ***will not compile for Windows*** as it
stands.

## Contents

- [Container image](#container-image)
  - [1. Without a config file, the container uses the built-in defaults](#1-without-a-config-file-the-container-uses-the-built-in-defaults)
  - [2. Pass your own config](#2-pass-your-own-config)
  - [3. Keep the output](#3-keep-the-output)
  - [4. nmap and masscan need root in the image](#4-nmap-and-masscan-need-root-in-the-image)
  - [Pin the version](#pin-the-version)
  - [Reading the docs offline](#reading-the-docs-offline)
- [Prebuilt binary](#prebuilt-binary)
- [Build from source](#build-from-source)
- [Arch Linux PKGBUILD](#arch-linux-pkgbuild)
- [Where the config comes from](#where-the-config-comes-from)
- [Running tools that need root](#running-tools-that-need-root)
- [Metasploit](#metasploit)

## Container image

The image is `ghcr.io/tidynest/raven-nest-mcp`. It
- is built on Kali rolling,
- runs as a non-root user,
- contains `raven-server` plus the 22 wrapped tools.

***Metasploit is not in the image***, because it roughly doubles the size.

**The shortest client entry:**

```json
{
  "mcpServers": {
    "raven-nest": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "ghcr.io/tidynest/raven-nest-mcp:latest"]
    }
  }
}
```

That is enough to try it.

Before you use it on real work, ***read the next four points***.

### 1. Without a config file, the container uses the built-in defaults

The image carries no config in a place the server looks, so it starts on the
defaults compiled into the binary.

**Those differ from `config/default.toml` in this repository:**

- **The engagement scope** is ***off***.
- **The context budget** is off.
- **`sudo_tools`** is empty, which is what you need in the container.
- **`gitleaks` and `trufflehog`** are missing from the built-in allowlist ***in
  version 0.4.2 and earlier***. On those images both tools answer "tool not
  allowed" until you supply a config that lists them. Later versions allow
  them by default.

### 2. Pass your own config

**Step 1.** Copy the reference config out of the image:

```bash
docker run --rm --entrypoint cat ghcr.io/tidynest/raven-nest-mcp:latest /usr/share/doc/raven-nest-mcp/default.toml > raven.toml
```

**Step 2.** Edit `raven.toml`:
- set `sudo_tools = []`, because ***the container has no `sudo`***,
- turn on `[scope]`,
- set `output_dir` as described below.

**Step 3.** Mount it back and name it in `RAVEN_CONFIG`:

```json
{
  "mcpServers": {
    "raven-nest": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/absolute/path/to/raven.toml:/etc/raven-nest/config.toml:ro",
        "-e", "RAVEN_CONFIG=/etc/raven-nest/config.toml",
        "-v", "raven-nest-data:/var/lib/raven-nest",
        "ghcr.io/tidynest/raven-nest-mcp:latest"
      ]
    }
  }
}
```

### 3. Keep the output

With `--rm` and no volume, these ***disappear when the client closes the
server***:
- findings,
- reports,
- discovery data,
- the audit log.

To keep them, mount a volume and point `output_dir` inside it:

```toml
[execution]
output_dir = "/var/lib/raven-nest/data"
```

`/var/lib/raven-nest` is the home directory of the container user, uid 10001.

- **A named volume** mounted there should take that ownership on first use.
- **A bind-mounted host directory** has to be writable for uid 10001.

**Wordlists follow the same rule.**
***The image ships no SecLists***, and the server only reads wordlists from
- `/usr/share/`,
- `/usr/lib/`,
- `output_dir`.

Mount your lists into one of those, for example
`-v /usr/share/seclists:/usr/share/seclists:ro`, or pass a `wordlist` path
that sits under `output_dir`.

The same applies to a repository you would like gitleaks or trufflehog to
scan.

### 4. nmap and masscan need root in the image

**Watch out:**
In the image, `run_nmap` and `run_masscan` ***do not work as the default
user***. This holds for every image since it went non-root, 0.4.2 included,
and for every nmap scan type, not only OS detection.

**Why:**
Both tools open raw sockets. The image runs as uid 10001, and a non-root
process in a container holds no capabilities, so `--cap-add=NET_RAW` and
`--cap-add=NET_ADMIN` have no effect on it. Earlier versions of this page and
the Dockerfile comments said those flags were enough. They are not.

**What you see:**
- nmap prints "Couldn't open a raw socket" and quits. The server still
  reports the call as a success, with no hosts and a nonsense host count.
- masscan prints "permission denied".

**Until the image is fixed,** run the container as root by adding this
before the image name:

```
"-u", "0"
```

That gives up the non-root user for the whole server. Root in a container
holds `NET_RAW` by default, which covers nmap. Add `"--cap-add=NET_ADMIN"` as
well if masscan needs it on your setup.

Every other tool in the image works as the default user.

### Pin the version

`latest` moves with each release.

For an engagement, ***pin a tag*** such as
`ghcr.io/tidynest/raven-nest-mcp:0.4.2`, so the tools and the server do not
change under you.

The image is also listed on the
[MCP Registry](https://registry.modelcontextprotocol.io) as
`io.github.tidynest/raven-nest-mcp`.

### Reading the docs offline

The image carries the main docs under `/usr/share/doc/raven-nest-mcp/`:

```bash
docker run --rm --entrypoint cat ghcr.io/tidynest/raven-nest-mcp:latest /usr/share/doc/raven-nest-mcp/USAGE.md
```

## Prebuilt binary

Each [GitHub release](https://github.com/tidynest/raven-nest-mcp/releases)
has `raven-server-<tag>-x86_64-unknown-linux-gnu.tar.gz` and a `.sha256` file
next to it.

**The archive holds**
- the binary,
- the README,
- the changelog,
- the licence,
- `default.toml`.

**Check the download:**

```bash
sha256sum -c raven-server-v0.4.2-x86_64-unknown-linux-gnu.tar.gz.sha256
```

The server ***does not look for `default.toml` beside the binary***. Either
- point at it with `RAVEN_CONFIG`, or
- move it to `config/default.toml` next to the binary.

***You install the scanners yourself***. See
[Host tools](USAGE.md#host-tools) and [Wordlists](USAGE.md#wordlists).

## Build from source

```bash
git clone https://github.com/tidynest/raven-nest-mcp.git
cd raven-nest-mcp
cargo build --release
```

The binary is `target/release/raven-server`.

With cargo's default `target/` directory, the server finds the repository's
`config/default.toml` on its own. Version 0.4.2 and earlier did not.

It ***does not find it*** if your build output goes somewhere else, for
example through `CARGO_TARGET_DIR`. Naming the config in the client entry
works in every case:

```json
{
  "mcpServers": {
    "raven-nest": {
      "command": "/absolute/path/to/raven-nest-mcp/target/release/raven-server",
      "args": [],
      "env": { "RAVEN_CONFIG": "/absolute/path/to/raven-nest-mcp/config/default.toml" }
    }
  }
}
```

If the server finds no config at all, it starts on ***the built-in
defaults***.

**Local model?**
Name the server `raven` with no hyphen.
[LOCAL_AI_INTEGRATION.md](LOCAL_AI_INTEGRATION.md) explains why.

## Arch Linux PKGBUILD

`packaging/aur/PKGBUILD` builds the server from the release tarball and lists
every scanner as an optional dependency.

```bash
cd packaging/aur
makepkg -si
```

The package installs the reference config to
`/usr/share/raven-nest-mcp/default.toml`. Copy it somewhere you own and point
`RAVEN_CONFIG` at the copy.

***The package is not on the AUR yet***. When it is, this section will say
so.

## Where the config comes from

The server takes ***the first of these that loads***:

1. **The file named in the `RAVEN_CONFIG` environment variable**.
2. **`~/.config/raven-nest/config.toml`**, or the same path under
   `$XDG_CONFIG_HOME` if you have set it.
3. **`/etc/raven-nest/config.toml`**.
4. **`config/default.toml` in the directory of the binary**, or up to two
   directories above it.
   For a binary at `target/release/raven-server` that means
   `target/release/config/`, `target/config/` and the repository's own
   `config/`. Version 0.4.2 and earlier stopped one level short of the
   repository root.
5. **`config/default.toml` in the working directory**.
6. **The built-in defaults**.

Steps 2 and 3 are new after version 0.4.2. They are the simplest place to put
a config: copy the reference file there and the server finds it wherever the
binary lives.

**How to see which one it took:**
The server writes the choice to stderr at startup, for example
- `config loaded from RAVEN_CONFIG=/etc/raven-nest/config.toml`, or
- `no config found, using built-in defaults`.

**Watch out:**
- **After version 0.4.2**, a config file that exists but does not load
  ***stops the server***, and the error names the file.
- **In version 0.4.2 and earlier**, a file in `RAVEN_CONFIG` that is missing
  or does not parse is skipped with a warning, and the server moves on to the
  next step. Check that first log line whenever your config carries a scope.

The full reference for every section is in
[USAGE.md](USAGE.md#configuration).

## Running tools that need root

Outside the container, `masscan` and nmap OS detection need root.

You can grant that per tool ***without running the whole server as root***:

1. **Install `config/sudoers-raven-nest`** to `/etc/sudoers.d/raven-nest`
   after replacing `CHANGE_ME` with your user name.
2. **List the tools** in `[safety] sudo_tools`.

Details are in [USAGE.md](USAGE.md#sudo_tools---privilege-escalation).

## Metasploit

The `msf_*` tools need an `msfrpcd` that you run yourself, on the host or in
another container. See [METASPLOIT.md](METASPLOIT.md).
