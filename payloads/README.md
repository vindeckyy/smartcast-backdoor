# Payloads

`busybox-armv7l` (static ARMv7 busybox) is **not vendored** — it is GPLv2 and the
`/install` RCE path it was used with is dead on 2025+ VIZIO OS builds.

If you are reproducing the legacy 2021 ViziOwn technique on an old build, fetch a
static busybox yourself (e.g. from the `busybox.net` binaries or your distro's
`busybox-static` package) and place it at `payloads/busybox-armv7l`.
See `viziown.sh` for the exact usage.
