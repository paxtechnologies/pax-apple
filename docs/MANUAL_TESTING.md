# Manual testing notes

These step-by-step notes were moved out of the README to keep it short. For the current checklist, see [HARDWARE_TEST.md](HARDWARE_TEST.md).

### Test it on your Mac today (step by step)

You'll use the folder `~/pax-apple`, the key in `~/.pax-test-key`, and a local server. Allow about 30
minutes.

**0. Before you start**

* Turn FileVault on if it isn't (System Settings › Privacy & Security › FileVault), and **write the
  recovery key down somewhere off this Mac**. If FileVault is already on and you don't have the key,
  make a new one: `sudo fdesetup changerecovery -personal` (it prints it).
* Make a Time Machine backup, or check your files are in iCloud.
* Nothing to install first (v0.8.6).
* Make sure no other administrator account exists (System Settings › Users & Groups). Pax refuses if
  there is one.
* Pax quarantines VPN apps and the browsers it can't manage the moment it starts (Opera, Vivaldi, Arc,
  Orion, Tor, Tailscale, WireGuard, NordVPN and so on; full list in `guard/guard_config.py`), and
  disconnects any connected VPN. Quit them first. They come back when you remove Pax.

**1. Replace the code** (keeps your key and database):

```bash
cd ~ && mv pax-apple pax-apple-0.3 && unzip ~/Downloads/pax-apple-v0.4.zip -d ~
```

**2. Run the server with a 1-day wait** (Terminal window 1, leave it running):

```bash
cd ~/pax-apple/server
python3 -m venv .venv && source .venv/bin/activate && pip install -q -r requirements.txt
export PAX_SERVER_KEY="$(cat ~/.pax-test-key)"
export PAX_DB_PATH=~/pax-test.sqlite3
export PAX_MIN_WAIT_SECONDS=86400 PAX_DEFAULT_WAIT_SECONDS=86400
uvicorn --factory pax_server.main:create_app --host 127.0.0.1 --port 8080
```

If your account in `~/pax-test.sqlite3` already has a 3-day wait, use a fresh database
(`export PAX_DB_PATH=~/pax-mac-test.sqlite3`): Pax notices the old saved sign-in no longer works and
asks for an email again. The first hour is the grace period (removal is instant). To try the real
1-day timer later, restart the server with `export PAX_GRACE_SECONDS=0`.

**3. Build and install the app** (Terminal window 2):

```bash
cd ~/pax-apple/mac-app && ./scripts/build-dmg.sh && open dist/Pax-0.4.dmg
```

Drag Pax to Applications (replace the old one), then open it.

**4. Protect this Mac** (v0.7.0 flow): on the first screen click **This Mac** (or ⇧⌘M). Step 1: keep
the choices or change them, **Continue**. Step 2: pick **24 hours** (needs a test server started with
`PAX_MIN_WAIT_SECONDS=86400`) or **72 hours**, enter an email, **Continue**. Step 3: tick the agreement
and backup boxes, type your Mac password and click **Protect my Mac**. If Pax asks about FileVault or
shows a warning, tick the box and click **Protect my Mac** again. When System Settings opens, install
**Pax (this Mac)** under General › Device Management, then click **I've installed it**. Wait for
"You're protected". If anything fails, note the code (e.g. `PAX-GUARD-003`) and use *Copy details*.

**5. Check it worked** (Terminal):

```bash
dseditgroup -o checkmember -m "$USER" admin        # → no alex is NOT a member of admin
dscl . -read /Users/paxadmin IsHidden              # → IsHidden: 1
pgrep -fl pax_guard.py                             # the daemon is running
tail -n 20 /var/log/pax-guard.log                  # hosts block updated, pf anchor loaded
grep -c '^0.0.0.0 ' /etc/hosts                     # ~150,000 with ad blocking on
SITE=$(python3 common/pax_restricted.py --sample | head -n 1)   # a restricted test site (kept encoded)
dscacheutil -q host -a name "$SITE"                # → ip_address: 0.0.0.0
curl -sS -m 5 "https://www.$SITE" -o /dev/null     # fails
dig +short @8.8.8.8 "$SITE"                        # times out (pf blocks other DNS servers)
nc -z -G 3 1.1.1.1 853 || echo "DoT blocked"
```

In Safari, Chrome and Firefox:

* The `--sample` site (or any restricted site) doesn't load, in normal **and** private/Incognito windows.
* `reddit.com` doesn't load (CleanBrowsing Family blocks mixed-content sites).
* Search Google for something restricted: results are filtered and SafeSearch can't be switched off
  (Chrome/Edge/Brave by policy, every browser by CleanBrowsing's DNS). YouTube is in Restricted Mode.
* `chrome://policy` lists Pax's policies; `chrome://flags` is blocked; installing any extension except
  a password manager (1Password, Bitwarden, LastPass, Dashlane, Proton Pass, iCloud Passwords) is blocked.
* Incognito still opens (on purpose).

Bypass checks:

```bash
cp -R /System/Applications/Chess.app ~/Applications/"Tor Browser.app"   # a harmless stand-in
sleep 40; ls ~/Applications                                            # gone (quarantined)
```

Blocked sites: in Pax › Blocked sites, add `example.com`; within about 30 s
`dscacheutil -q host -a name example.com` shows `0.0.0.0`. Ads: `dscacheutil -q host -a name
fls.doubleclick.net` shows `0.0.0.0`; switch **Block ads and trackers** off on the Protect this Mac
screen and within a minute it resolves normally again.

**6. Undo it** (during the grace week it's instant): Protect this Mac › **Request removal** › **Reveal
the password** › **Remove Pax from this Mac**. Then check `dseditgroup -o checkmember -m "$USER" admin`
says yes, `grep -c 'BEGIN PAX' /etc/hosts` is 0, the profile is gone from System Settings, and
`dscl . -read /Users/paxadmin` says the record doesn't exist. Log out and back in.


## Test v0.5 on your Mac (step by step)

Start from v0.4's test steps (server with the 1-day wait, `~/.pax-test-key`). If this Mac is
protected by v0.4, remove Pax first (Protect this Mac › Request removal › Reveal › Remove), because
pax-guard and the profile must be reinstalled to pick up v0.5.

1. **Code**: `cd ~ && mv pax-apple pax-apple-0.4 && unzip ~/Downloads/pax-apple-v0.5.zip -d ~`.
2. **Server** (window 1): as in v0.4 step 2 (same key and database; a `block_remote_desktop` column is
   added automatically).
3. **Extension first** (before the Mac is locked): `cd ~/pax-apple/extension && python3 build.py`, load
   `dist/chrome` unpacked in Chrome and `dist/firefox/manifest.json` as a temporary add-on in Firefox.
   Open an image-heavy news site: pictures appear blurred, then clear within a second or two. Search
   images for "swimwear": some stay blurred and clear on click. Add the site from the toolbar button:
   reload, no pre-blur. Remove the unpacked/temporary copies afterwards.
4. **(Optional) sign the Firefox add-on** as above so the protected Mac's release Firefox installs it.
5. **Build**: `cd ~/pax-apple/mac-app && UNIVERSAL=1 ./scripts/build-dmg.sh && open dist/Pax-0.5.dmg`,
   drag Pax to Applications. In *Settings › Advanced* (sidebar, or ⌘,) enter `http://127.0.0.1:8080/` (v0.8.5
   and later default to `https://api.paxpeace.com/`); *Test* says a server answered.
6. **Protect this Mac** as in v0.4 step 4 (quit any VM apps first).
7. **Check** (Terminal):

   ```bash
   grep -c '^0.0.0.0 ' /etc/hosts                       # ~165,000 with ads on
   dscacheutil -q host -a name sensepc.com              # 0.0.0.0 (bypass, always)
   dscacheutil -q host -a name remotedesktop.google.com # 0.0.0.0 (remote desktop on)
   sudo pfctl -a com.apple/250.org.paxpeace.pax -sr | grep 3389   # remote-desktop ports blocked
   ls -l /Library/PaxGuard/bin/lists /Library/PaxGuard/extensions
   ```

   In Chrome `chrome://policy` lists `URLBlocklist` with `sensepc.com`; `browserling.com` won't load.
   In Firefox `about:policies` shows `WebsiteFilter` and the `pax-image-blur@paxmobile.org` entry;
   `about:addons` lists Pax Image Blur if the XPI was signed (unsigned: Firefox refuses it, as expected).
   VMs: `cp -R /System/Applications/Chess.app ~/Applications/UTM.app; sleep 40; ls ~/Applications`
   (gone).
8. **Remote desktop switch**: Blocked sites › *Block remote desktop* off › confirm: a 72 h countdown
   appears and `remotedesktop.google.com` still resolves to 0.0.0.0. *Cancel* it. (To see it take
   effect quickly, restart the server with `PAX_BLOCKLIST_DELAY_SECONDS=120`.) Turning it back on is
   instant.
9. **Undo** as in v0.4 step 6.

'''
