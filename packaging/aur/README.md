# AUR packaging

Source-build PKGBUILD for the [`raven-nest-mcp`](https://aur.archlinux.org/packages/raven-nest-mcp)
AUR package. The server needs only `glibc`/`gcc-libs`/`openssl`; every scanner it
drives is an `optdepends` (install only what you use - many are in BlackArch/AUR).

## Test before publishing

```sh
cd packaging/aur
makepkg -f                       # build + package locally (full release compile)
namcap PKGBUILD raven-nest-mcp-*.pkg.tar.zst   # lint sources and built package
```

## Publish to the AUR

```sh
git clone ssh://aur@aur.archlinux.org/raven-nest-mcp.git aur-raven
cp PKGBUILD aur-raven/
makepkg --printsrcinfo -p PKGBUILD > aur-raven/.SRCINFO   # regenerate, never hand-edit
cd aur-raven && git add PKGBUILD .SRCINFO && git commit && git push
```

Requires your AUR account + registered SSH key (publishing is not done from this repo).

## Updating for a new release

Bump `pkgver`, reset `pkgrel=1`, refresh `sha256sums` for the new tag's source
tarball (`updpkgsums`), regenerate `.SRCINFO`, then publish.

## A `-bin` variant

Once the release workflow attaches a prebuilt `raven-server-<tag>-x86_64-unknown-linux-gnu.tar.gz`
to each GitHub release, a `raven-nest-mcp-bin` package can source that artifact
directly (no `cargo`/Rust build, just `makedepends=()` + the tarball's checksum).
