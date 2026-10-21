# SPDX-License-Identifier: GPL-3.0-only
"""The account step, kept pluggable.

Today the Windows set-up uses the same account as the Mac: an email address (a new
account, or the existing one after an emailed 6-digit code). The iOS app 1.2 is moving
to a one-tap set-up with an anonymous device account; when the server offers that, an
``AnonymousDeviceAccount`` provider slots in here without touching the rest of the flow.
It is deliberately not built yet.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from .escrow import EscrowClient, EscrowError


@dataclass
class AccountResult:
    state: str                     # "ready" | "code_sent"
    sent_to: Optional[str] = None


class AccountProvider(ABC):
    kind = "abstract"

    @abstractmethod
    def ensure(self, escrow: EscrowClient) -> AccountResult:
        """Leave ``escrow.token`` set to a working account token, or say what the person
        must do first (enter an emailed code)."""


class EmailAccount(AccountProvider):
    """Mac behaviour (SetupModel.saveWaitAndAccount): a saved token that still works is
    kept; otherwise register the email; if it already has an account (409), a code goes
    to it and the next call signs in with that code."""
    kind = "email"

    def __init__(self, email: str, code: Optional[str] = None, label: str = "Windows PC"):
        self.email = (email or "").strip()
        self.code = code
        self.label = label
        self.code_sent_to: Optional[str] = None

    def ensure(self, escrow: EscrowClient) -> AccountResult:
        if escrow.token:
            try:
                escrow.account_summary()
                return AccountResult("ready")
            except EscrowError as exc:
                if exc.status != 401:
                    raise
                escrow.token = None       # token for a reset server: register again
        if self.code_sent_to and self.code:
            acct = escrow.sign_in(self.code_sent_to, self.code, self.label)
            escrow.token = acct["token"]
            self.code_sent_to, self.code = None, None
            return AccountResult("ready")
        try:
            acct = escrow.register_account(self.email)
        except EscrowError as exc:
            if exc.status != 409:
                raise
            escrow.start_sign_in(self.email)
            self.code_sent_to = self.email
            return AccountResult("code_sent", self.email)
        escrow.token = acct["token"]
        return AccountResult("ready")


class AnonymousDeviceAccount(AccountProvider):
    """Placeholder for the one-tap set-up planned with iOS app 1.2 (an anonymous device
    account, no email). Not built: the server has no such route yet."""
    kind = "anonymous"

    def ensure(self, escrow: EscrowClient) -> AccountResult:   # pragma: no cover - placeholder
        raise NotImplementedError("Anonymous device accounts aren't available yet.")
