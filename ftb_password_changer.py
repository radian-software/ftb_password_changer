#!/usr/bin/env python3

import argparse
import subprocess
import sys
from typing import Callable

import bs4
import Levenshtein
import requests
import yaml


EXAMPLE_FINGERPRINT = "b0b4ccc5a8c10afddb4196f2d522d4d48c44743b"
EXAMPLE_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
)


class Config:
    def __init__(self, fname: str):
        with open(fname) as f:
            self.cfg = yaml.safe_load(f)
        self.cache = {}

    def _cache(self, k: str, f: Callable[[], str]):
        if k in self.cache:
            return self.cache[k]
        v = f()
        self.cache[k] = v
        return v

    def _expand(self, s: str) -> str:
        if not s.startswith("!"):
            return s
        if s.startswith("!!"):
            return s[2:]
        return self._cache(
            s,
            lambda: (
                subprocess.run(
                    ["bash", "-c", s[1:]], stdout=subprocess.PIPE, check=True
                )
                .stdout.decode()
                .strip()
            ),
        )

    @property
    def username(self) -> str:
        return self._expand(self.cfg["username"])

    @property
    def password(self) -> str:
        return self._expand(self.cfg["password"])

    def security_answer(self, question: str) -> str:
        for entry in self.cfg["questions"]:
            if Levenshtein.distance(question, entry["q"]) < 3:
                return self._expand(entry["a"])
        raise RuntimeError(f"no matches for security question {repr(question)}")


class FTBSession:
    def __init__(self, cfg: Config):
        self.sess = requests.Session()
        self.cfg = cfg

    def close(self):
        self.sess.close()

    def get_access_your_account(self) -> str:
        resp = self.sess.get(
            "https://webapp.ftb.ca.gov/MyFTBAccess/Login/AccessYourAccount",
            headers={
                "user-agent": EXAMPLE_USER_AGENT,
            },
        )
        resp.raise_for_status()
        soup = bs4.BeautifulSoup(resp.text, "lxml")
        elt = soup.find("input", {"name": "__RequestVerificationToken"})
        assert isinstance(elt, bs4.Tag), elt
        val = elt.get("value")
        assert isinstance(val, str), val
        return val

    def post_access_your_account(self, verification_token: str):
        for key in self.sess.cookies:
            print(key)
        resp = self.sess.post(
            "https://webapp.ftb.ca.gov/MyFTBAccess/Login/AccessYourAccount",
            data={
                "UserName": self.cfg.username,
                "Password": self.cfg.password,
                "__RequestVerificationToken": verification_token,
                "_Fingerprint": EXAMPLE_FINGERPRINT,
            },
            headers={
                "user-agent": EXAMPLE_USER_AGENT,
            },
            allow_redirects=False,
        )
        resp.raise_for_status()
        assert resp.status_code in {301, 302}, resp.status_code


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()
    cfg = Config("ftb.yaml")
    s = FTBSession(cfg)
    csrf = s.get_access_your_account()
    s.post_access_your_account(csrf)


if __name__ == "__main__":
    main()
    sys.exit(0)
