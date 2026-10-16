# Licences for the iPhone helper runtime bundled in Pax.app (v0.8.6)

`mac-app/scripts/build-device-helper.sh` copies this folder into
`Pax.app/Contents/Resources/device/python/LICENSES/`.

* `LICENSE.cpython.txt`: CPython 3.12 (PSF-2.0 and the historical CNRI/BeOpen/CWI terms),
  as built by python-build-standalone (https://github.com/astral-sh/python-build-standalone,
  release 20261009).
* Libraries that python-build-standalone links into that CPython build, per its
  `PYTHON.json` (texts taken from its `full` archive for the same release):
  OpenSSL 3 (`LICENSE.openssl-3.txt`, Apache-2.0), libffi (MIT), expat (MIT), mpdecimal
  (BSD-2-Clause), liblzma (0BSD / public domain), bzip2 (bzip2-1.0.6), zlib (Zlib),
  SQLite (public domain), libedit (BSD-3-Clause), ncurses (X11) and libuuid
  (BSD-3-Clause). Tcl/Tk is removed from the bundle.
* `LICENSE.bpylist2.txt`: bpylist2's MIT licence. Its wheel carries no licence file, so
  the text from its README is kept here.
* Every other bundled Python package carries its licence in its own
  `site-packages/<name>-<version>.dist-info/` folder. The full list, with licences and
  source links, is in `docs/DEPENDENCIES.md` and `THIRD_PARTY_NOTICES.md`.

All of these licences are compatible with Pax's GPL-3.0-only.
