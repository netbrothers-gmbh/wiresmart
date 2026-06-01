# NB WireSmart

NB WireSmart is a Linux GUI to easily use your preconfigured WireGuard tunnels.

## Prerequisites

- Linux
- Preconfigured WireGuard tunnels (`/etc/wireguard/*.conf`)
- `wg-quick` (on most distributions provided by the `wireguard-tools` package)
- `pkexec` (optional for unprivileged startup, part of Polkit, usually preinstalled)

## Privilege Behavior

NB WireSmart starts unprivileged and will prompt for elevation on startup if it
detects that it needs elevated access to manage WireGuard tunnels.

## Releases

NB WireSmart currently ships as AppImage only. Head over to the
[releases page](https://github.com/netbrothers-gmbh/wiresmart/releases) and find
the latest binary for your architecture.

## Usage

Make the AppImage executable and run it.

```bash
chmod +x wiresmart-*.AppImage
./wiresmart-*.AppImage
```

## Technologies

NB WireSmart is created with [Rust](https://rust-lang.org/) and [egui](https://www.egui.rs/).

## License

NB WireSmart is released under the GPLv3 license. See the bundled [LICENSE](LICENSE) file for details.

## Support / Feature Requests

If you need help or additional features feel free to contact us, open an issue
or submit a PR.

## Author

[Thilo Ratnaweera, NetBrothers GmbH](https://netbrothers.de)


[![NetBrothers Logo](https://netbrothers.de/wp-content/uploads/2020/12/netbrothers_logo.png)](https://netbrothers.de)