# SPDX-License-Identifier: GPL-3.0-only
"""Every sentence the Windows set-up shows, in one place, so the wording rules are
tested (tests/test_wording.py): calm and neutral, "turn-off wait", "someone you trust",
the same agreement as the Mac. Mac originals: mac-app/Sources/PaxCore/TurnOffWait.swift,
TrialDay.swift, SupportRelease.swift and Pax/Views/SetupFlowView.swift."""
from __future__ import annotations

TITLE = "Pax for iPhone set-up"
SUBTITLE = "Set up Pax on an iPhone or iPad from this PC."
NOT_FOR_PC = ("This sets up your iPhone or iPad only. It doesn't filter or protect this PC.")

# Steps (the progress rail)
STEP_TITLES = ["Plug in", "Get ready", "Turn-off wait", "Lock it in", "Done"]

# 1. Plug in
CONNECT_TITLE = "Plug in your iPhone or iPad"
CONNECT_HELP = ("Use a USB cable. Wake the phone and enter your passcode. If it asks "
                "\u201cTrust This Computer?\u201d, tap Trust and enter your passcode.")
CONNECT_SEARCHING = "Looking for your iPhone or iPad\u2026"
CONNECT_NEEDS_TRUST = ("Tap Trust on your {device} and enter your passcode. Pax keeps looking.")
CONNECT_FOUND = "Found {name} (iOS {ios})."

# Apple's driver (Apple Mobile Device Service)
DRIVER_TITLE = "Windows needs Apple's free device driver"
DRIVER_HELP = ("Pax talks to your iPhone through Apple's own driver. Install Apple's free "
               "\u201cApple Devices\u201d app from the Microsoft Store (or iTunes), open it once with "
               "your phone plugged in, then come back here.")
DRIVER_STOPPED = ("Apple's driver is installed but not running. Restart this PC, or open the Apple "
                  "Devices app once, then try again.")
DRIVER_BUTTON = "Open the Microsoft Store"
DRIVER_RECHECK = "Check again"

# 2. Get ready
READY_TITLE = "Get your {device} ready"
READY_SUBTITLE = ("Pax keeps everything on your {device}. It restarts once. About 10 to 20 minutes.")
FIND_MY_OFF = ("Find My is off (Settings \u203a your name \u203a Find My). You'll turn it back on at the end.")
PASSCODE_NOTE = ("Keep your passcode on and close at hand: you'll enter it after the restart.")
BACKUP_WITH_PAX = "Back up with Pax"
BACKUP_WITH_PAX_NOTE = "Recommended. Takes a while."
BACKUP_DONE = "Backup saved and checked on this PC."
BACKUP_OWN = ("Or: I backed up this {device} today with iCloud, the Apple Devices app or iTunes, "
              "and it finished.")

# 3. Turn-off wait (same choices as the Mac: 1 day, 3 days (recommended), 7 days, Custom)
WAIT_TITLE = "How long should turning Pax off take?"
WAIT_HELP = ("If you ever decide to switch Pax off, you'll ask first, then wait this long before it "
             "turns off. You can cancel any time during the wait. Choose a time that would outlast a "
             "bad night.")
WAIT_ALSO_APPLIES = "The same wait applies before a blocked site or app is unblocked."
WAIT_RECOMMENDED = "Recommended"
WAIT_CUSTOM = "Custom"
WAIT_CUSTOM_NOTE = ("You can make it longer any time. Making it shorter only counts once your current "
                    "turn-off wait has passed.")
EMAIL_LABEL = "Your email"
EMAIL_NOTE = "Pax writes only when someone asks to change or turn off Pax. Nothing else."
CODE_SENT = ("{email} already has a Pax account. We emailed it a code: enter it to use the same "
             "account, so your devices share one list.")
CODE_LABEL = "6-digit code"
TRUSTED_LABEL = "Someone you trust (optional)"
TRUSTED_NOTE = "They're told if you ask to turn Pax off. They never have to approve anything."
TRIAL_LINE = ("First time setting up Pax? Your first 24 hours are a trial day: you can turn Pax off any "
              "time, with no wait. After that, your turn-off wait applies by itself.")
SUPPORT_CHECKBOX = "Allow verified support release (recommended)"
SUPPORT_DETAIL = ("If you ever face a genuine emergency, Pax support can check it and give you a one-time "
                  "code that removes Pax from this device only. Your trusted person is told first.")

# 4. Lock it in
AGREEMENT = ("I'm 18 or over, and this {device} is mine or my child's. I understand that turning Pax "
             "off takes my turn-off wait ({wait}).")
PROTECT_BUTTON = "Protect my {device}"
WORKING_TITLE = "Protecting your {device}"
WORKING_HELP = "Keep the cable connected and the {device} awake."
ON_PHONE_TITLE = "On your {device}"
ON_PHONE_STEPS = [
    "Leave it while it restarts by itself.",
    "When it says \u201cPress home to upgrade\u201d, press the Home button, or swipe up.",
    "Enter your passcode.",
    "If it asks \u201cTrust This Computer?\u201d, tap Trust and enter your passcode.",
]
ON_PHONE_LIVE_STEP = ("If it shows \u201cRestore Completed\u201d, stay on that screen until Pax says so.")
TAPPED_TRUST = "I tapped Trust"
PLUGGED_BACK = "I plugged it back in"
WAITING_LONG = ("Still waiting after 5 minutes. Unplug the {device}, plug it back in and wake it. "
                "Pax keeps looking.")
NEARLY_TITLE = "Nearly there"
NEARLY_LIVE = ("On your {device}, tap Continue on \u201cRestore Completed\u201d (if it's showing) and "
               "finish the few setup screens. Your Apple Account may ask for its password once.")
NEARLY_RESTORED = "Wake your {device}. If any setup screens appear, finish them."
TURN_ON_BUTTON = "Turn on protection"
ONE_TAP_TITLE = "One tap on your {device}"
ONE_TAP_STEPS = [
    "Open Settings and tap \u201cProfile Downloaded\u201d near the top.",
    "Tap Install, enter your passcode, and tap Install again.",
    "Keep it awake and connected, then click below.",
]
INSTALLED_BUTTON = "I installed it"

# Phone states while Pax waits for it after the restart (Mac: PhoneConnectState.instruction)
PHONE_STATE = {
    "paired": "Connected.",
    "trust_requested": "Tap Trust on the {device} and enter your passcode, then click \u201cI tapped Trust\u201d.",
    "locked": "Wake the {device} (press Home or swipe up, then enter your passcode).",
    "not_found": "Waiting for the {device} to come back. Keep the cable plugged in.",
    "denied": "The {device} said Don't Trust. Unplug it, plug it back in, wake it and tap Trust.",
}

# Progress lines
PROGRESS = {
    "preflight": "Checking your {device}\u2026",
    "restoring": "Preparing your {device}. It will restart by itself.",
    "waiting": "Waiting for your {device}. Follow the steps below.",
    "confirming": "Making sure your {device} is ready\u2026",
    "supervised": "Your {device} is ready for protection.",
    "protecting": "Turning on protection\u2026",
    "escrow": "Handing the removal password to Pax. You will not see it.",
    "installing": "Installing protection on {name}\u2026",
}

# 5. Done
DONE_TITLE = "You're protected"
DONE_SUBTITLE = ("Everything on your {device} is where you left it. Your first 24 hours are a trial day: "
                 "you can turn Pax off with no wait until then.")
DONE_TURN_OFF_LATER = ("To turn Pax off later, sign in with the same email in Pax on a Mac. Turning Pax off "
                       "from this PC comes in a later version.")
FIND_MY_BACK = "Turn Find My back on"
FIND_MY_BACK_HELP = "Settings \u203a your name \u203a Find My. It protects you if the phone is lost."
LIMITS_NOTE = ("Good to know: a full restore of the {device} from a computer (recovery mode) still removes "
               "Pax, as it removes everything else.")

# Errors (calm, with a support code in Details)
GENERIC_ERROR = "Something didn't work. Nothing on your {device} was locked."
TRY_AGAIN = "Try again"
DETAILS = "Details"
