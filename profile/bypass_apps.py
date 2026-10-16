# SPDX-License-Identifier: GPL-3.0-only
"""Default list of iOS/iPadOS apps Pax blocks because they are commonly used to
get around DNS filtering.

Every bundle ID below was looked up on 2026-10-12 with Apple's public iTunes
Search API (https://itunes.apple.com/search?entity=software&country=gb&term=...),
which returns the App Store `bundleId` for each listing. Run
`python3 profile/refresh_bypass_apps.py` before each release: App Store
listings come and go.

Why these apps:
  * Tor / onion browsers route traffic over Tor, so DNS filtering never sees it.
  * Browsers with a built-in proxy/"free VPN" (Opera, Aloha, Psiphon) tunnel
    browser traffic themselves; this is NOT a system VPN, so the
    allowVPNCreation restriction does not stop it.
  * VPN apps: allowVPNCreation=false already stops unmanaged apps creating VPN
    configurations on iOS 18+, but blocking the apps is a second layer and also
    covers older iOS versions (per Apple's schema, before iOS 18 unmanaged apps
    could still create VPN configurations).
"""

# (bundle_id, App Store name at lookup time, reason)
DEFAULT_BYPASS_APPS = [
    # Tor / onion routing
    ("com.miketigas.OnionBrowser", "Onion Browser", "tor"),
    ("org.torproject.orbot", "Orbot", "tor"),
    ("ch.b-eng.tor", "TOR Browser: OrNET Onion + VPN", "tor"),
    ("com.roundcherryapps.vpnTor", "TOR Browser: VPN+Onion Browser", "tor"),
    # Browsers with built-in proxy / VPN
    ("com.opera.OperaTouch", "Opera Browser with VPN", "browser-proxy"),
    ("com.opera.gx", "Opera GX", "browser-proxy"),
    ("com.alohabrowser.alohabrowser", "Aloha Browser - Private VPN", "browser-proxy"),
    ("com.psiphon3.browser", "Psiphon Browser", "browser-proxy"),
    ("com.hcloud.vpnbrowser", "Private Browser - VPN Proxy", "browser-proxy"),
    # VPN / tunnelling apps
    ("ca.psiphon.Psiphon", "Psiphon VPN", "vpn"),
    ("com.nordvpn.NordVPN", "NordVPN", "vpn"),
    ("com.expressvpn.iosvpn", "ExpressVPN", "vpn"),
    ("com.surfshark.vpnclient.ios", "Surfshark", "vpn"),
    ("ch.protonmail.vpn", "Proton VPN", "vpn"),
    ("com.windscribe", "Windscribe", "vpn"),
    ("com.tunnelbear.ios.TunnelBear", "TunnelBear", "vpn"),
    ("com.anchorfree.hss", "Hotspot Shield", "vpn"),
    ("com.cloudflare.1dot1dot1dot1", "1.1.1.1 (WARP)", "vpn"),
    ("com.privateinternetaccess.ios.PIA-VPN", "Private Internet Access", "vpn"),
    ("com.cyberghostsrl.cyberghostvpn", "CyberGhost", "vpn"),
    ("com.eventur.Hide.me", "hide.me VPN", "vpn"),
    ("net.mullvad.MullvadVPN", "Mullvad VPN", "vpn"),
    ("mobi.mobilejump.freevpn", "VPN - Super Unlimited Proxy", "vpn"),
    ("com.allconnected.turbovpn", "Turbo VPN Private Browser", "vpn"),
    ("co.allconnected.vpnmaster", "VPN Proxy Master", "vpn"),
    ("com.freevpnapp.freevpn", "Free VPN - Fast & Secure Proxy", "vpn"),
]


def default_bundle_ids() -> list[str]:
    return [bid for bid, _name, _reason in DEFAULT_BYPASS_APPS]
