# SPDX-License-Identifier: GPL-3.0-only
"""Pax for iPhone set-up (Windows).

Sets up Pax's "Keep my data" protection on an iPhone or iPad from a Windows PC over USB,
the same way Pax.app does it from a Mac. It does NOT filter or protect the PC itself.

The USB work is done by the same code the Mac uses (device/pax_device.py and
device/seed.py, run as a separate helper process). The profile comes from
profile/make_profile.py and the turn-off wait is held by the same Pax server.
"""
VERSION = "0.1.0"
APP_NAME = "Pax for iPhone set-up"
