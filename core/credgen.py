#!/usr/bin/env python3
from __future__ import annotations
import secrets
import random
import string
from pathlib import Path
from typing import Iterable

# Lightweight generator utilities reused by GUI/Worker

# Default small pools; can be expanded by words file
_BASE_NAMES = [
    "ivan","niko","dima","luka","sofi","mira","max","alex","mari","toma",
    "jake","lena","vlad","pavel","dari","roma","tim","liza","yana","igor",
]

_WORDS = [
    "river","stone","shadow","nova","amber","pixel","cloud","storm","field",
    "delta","ember","cobalt","violet","matrix","orbit","neon","haze","lumen","frost",
]

_LEET = {
    'o': '0', 'O': '0',
    'i': '1', 'I': '1', 'l': '1',
    'e': '3', 'E': '3',
    'a': '4', 'A': '4',
    's': '5', 'S': '5',
}

class CredGenerator:
    def __init__(self, *, words_file: str | None = None, seed: int | None = None):
        self.rng = random.Random(seed) if seed is not None else random.Random(secrets.randbits(64))
        # load extra words if provided
        self.words: list[str] = list(_WORDS)
        if words_file:
            try:
                p = Path(words_file)
                if p.exists():
                    extra = [w.strip().lower() for w in p.read_text(encoding='utf-8', errors='ignore').splitlines() if w.strip().isalpha()]
                    # filter 3..10 chars
                    extra = [w for w in extra if 3 <= len(w) <= 10]
                    # dedupe
                    seen = set(self.words)
                    for w in extra:
                        if w not in seen:
                            self.words.append(w)
                            seen.add(w)
            except Exception:
                pass
        self.base_names = list(_BASE_NAMES)

    # ---- login (letters only) ----
    def _syllable(self) -> str:
        cons = "bcdfghjklmnpqrstvwxyz"
        vows = "aeiou"
        return self.rng.choice(cons) + self.rng.choice(vows)

    def _pronounceable(self, min_pairs: int = 2, max_pairs: int = 3) -> str:
        n = self.rng.randint(min_pairs, max_pairs)
        return "".join(self._syllable() for _ in range(n))

    def _only_letters(self, s: str) -> str:
        return "".join(ch for ch in s if ch.isalpha())

    def generate_login(self, min_len: int = 4, max_len: int = 30) -> str:
        style = self.rng.choices(["name","word","syll"], weights=[45,35,20])[0]
        if style == "name":
            base = self.rng.choice(self.base_names)
            if self.rng.random() < 0.35:
                base += self.rng.choice(self.words)[:self.rng.randint(2,3)]
        elif style == "word":
            base = self.rng.choice(self.words)
            if self.rng.random() < 0.4:
                base += self.rng.choice(self.words)[:self.rng.randint(1,2)]
        else:
            base = self._pronounceable(2, self.rng.choice([2,3,4]))
        # Базово только буквы
        login = self._only_letters(base.lower())
        # Иногда добавляем цифровой хвост для уникальности
        if self.rng.random() < 0.55:
            digits_tail = "".join(self.rng.choice(string.digits) for _ in range(self.rng.randint(1, 3)))
            login = f"{login}{digits_tail}"
        # Добиваем до минимальной длины (буквами или цифрами)
        if len(login) < min_len:
            alphabet = string.ascii_lowercase + string.digits
            need = min_len - len(login)
            login += "".join(self.rng.choice(alphabet) for _ in range(need))
        # Обрезаем при превышении
        if len(login) > max_len:
            login = login[:max_len]
        # Оставляем только буквы/цифры (на всякий случай)
        login = "".join(ch for ch in login if ch.isalnum())
        if not login:
            login = "user"
        return login

    # ---- nick from login ----
    def _apply_leet_like(self, s: str, p: float = 0.10) -> str:
        out = []
        for ch in s:
            if ch in _LEET and self.rng.random() < p:
                out.append(_LEET[ch])
            else:
                out.append(ch)
        return "".join(out)

    def derive_nick(self, login: str, min_len: int = 6, max_len: int = 20) -> str:
        nick = self._apply_leet_like(login, p=0.10)
        # occasional inner digit
        if self.rng.random() < 0.25 and len(nick) > 3:
            pos = self.rng.randint(1, min(len(nick)-1, 8))
            nick = nick[:pos] + str(self.rng.randrange(0, 10)) + nick[pos:]
        # tail: year, digits, or none
        tail_mode = self.rng.choices(["year","digits","none"], weights=[35,40,25])[0]
        if tail_mode == "year":
            year = str(self.rng.randrange(1987, 2011))
            nick += year
        elif tail_mode == "digits":
            nick += "".join(str(self.rng.randrange(10)) for _ in range(self.rng.randint(1, 4)))
        # enforce length and charset
        if len(nick) > max_len:
            nick = nick[:max_len]
        while len(nick) < min_len:
            nick += str(self.rng.randrange(10))
        nick = "".join(ch for ch in nick if ch.isalnum())
        if len(nick) > max_len:
            nick = nick[:max_len]
        while len(nick) < min_len:
            nick += str(self.rng.randrange(10))
        return nick

    # ---- password ----
    def generate_password(self, min_len: int = 6, max_len: int = 16) -> str:
        rng = secrets.SystemRandom()
        L = rng.randrange(min_len, max_len + 1)
        letters_lower = string.ascii_lowercase
        digits = string.digits
        if rng.random() < 0.6:
            wlen = rng.randrange(3, max(4, L - 1))
            w = "".join(rng.choice(letters_lower) for _ in range(wlen))
            d = "".join(rng.choice(digits) for _ in range(max(2, min(4, L - wlen))))
            pwd = (w + d)[:L]
        else:
            core = [rng.choice(letters_lower + digits) for _ in range(L)]
            pwd = "".join(core)
        if not any(c.isalpha() for c in pwd):
            pos = rng.randrange(len(pwd))
            pwd = pwd[:pos] + rng.choice(letters_lower) + pwd[pos+1:]
        if not any(c.isdigit() for c in pwd):
            pos = rng.randrange(len(pwd))
            pwd = pwd[:pos] + rng.choice(digits) + pwd[pos+1:]
        if rng.random() < 0.15:
            idxs = [i for i,c in enumerate(pwd) if c.isalpha()]
            if idxs:
                i = rng.choice(idxs)
                pwd = pwd[:i] + pwd[i].upper() + pwd[i+1:]
        return pwd

    def generate_triplet(self) -> tuple[str, str, str]:
        login = self.generate_login()
        nick = self.derive_nick(login)
        password = self.generate_password()
        return nick, login, password
