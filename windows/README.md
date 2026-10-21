# Pax for iPhone set-up (Windows)

Sets up Pax's "Keep my data" protection on an iPhone or iPad from a Windows PC over USB, the
same way Pax.app does it from a Mac. It does not filter or protect the PC.

- Plan, decisions, limits and the hardware checklist: [docs/WINDOWS_SETUP.md](../docs/WINDOWS_SETUP.md)
- `pax_windows/`: the window (tkinter), the set-up flow, the server client, the profile and
  identity, the Apple driver check. The USB work is `device/pax_device.py` (shared with the
  Mac), run as `pax-helper.exe` (`helper_main.py`).
- `python -m pax_windows --demo` (from this folder) walks the window with a canned phone.
- Tests: `python -m pytest windows/tests` (any OS; the GUI walk-through needs a display).
- Build: `.github/workflows/windows-setup.yml` (PyInstaller onedir + Inno Setup, unsigned).
