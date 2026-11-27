# SPDX-License-Identifier: MIT
"""Session-local translations with an English fallback."""
import gettext
from pathlib import Path

LOCALE = Path(__file__).resolve().parents[2] / "locale"
if not LOCALE.is_dir():
    LOCALE = Path(__file__).resolve().parents[4] / "share/locale"


def translation(languages=None):
    return gettext.translation("omarchy-enterprise", localedir=LOCALE,
                               languages=languages, fallback=True)


_ = translation().gettext
