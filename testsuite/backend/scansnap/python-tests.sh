#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later WITH SANE-exception
# Python 3 is optional for downstream make check; CI requires it explicitly.
command -v python3 >/dev/null 2>&1 || exit 77
PYTHONDONTWRITEBYTECODE=1; export PYTHONDONTWRITEBYTECODE
exec python3 -m unittest discover -s "${srcdir:-.}" -p 'test_scansnap_*.py' -v
