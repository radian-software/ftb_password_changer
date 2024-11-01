#!/usr/bin/env python3

import argparse
from datetime import datetime, timedelta
import re
import secrets
import string
import subprocess
import sys
import time
import traceback
from typing import Callable

import Levenshtein
import selenium.webdriver as webdriver
from selenium.webdriver.common.by import By
import yaml


def log(msg: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] ftb_password_changer: {msg}")


def pwgen(length: int):
    # FTB has undocumented password restrictions that needlessly block
    # some special characters from being used, likely due to
    # incompetence on their end. The error message is "Please use a
    # different password". Since they don't give any documentation
    # about their *actual* password policy, I've sampled all the
    # working special characters from my last eight passwords and am
    # only using those going forward.
    alphabet = string.ascii_letters + string.digits + r" !#%'()*+,-./;<=>@[\]{|~"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        invalid = False
        for r in ("[a-z]", "[A-Z]", "[0-9]", "[^a-zA-Z0-9]"):
            if not re.search(r, pw):
                invalid = True
                break
        if invalid:
            continue
        return pw


class Config:
    def __init__(self, fname: str, profile: str):
        with open(fname) as f:
            try:
                self.cfg = yaml.safe_load(f)["profiles"][profile]
            except KeyError as e:
                raise RuntimeError(
                    f"no profile named {repr(profile)} in {fname}"
                ) from e
        self.cache = {}

    def _cache(self, k: str, f: Callable[[], str]):
        if k in self.cache:
            return self.cache[k]
        v = f()
        self.cache[k] = v
        return v

    def _uncache(self, k: str):
        try:
            self.cache.pop(k)
        except KeyError:
            pass

    def _expand(self, s: str, k: str) -> str:
        if not s.startswith("!"):
            return s
        if s.startswith("!!"):
            return s[2:]
        return self._cache(
            k,
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
        return self._expand(self.cfg["username"], "username")

    @property
    def password(self) -> str:
        return self._expand(self.cfg["password"], "password")

    @password.setter
    def password(self, new_password: str):
        subprocess.run(
            ["bash", "-c", self.cfg["password_setter"]],
            input=(new_password + "\n").encode(),
            check=True,
        )
        self._uncache("password")

    def security_answer(self, question: str) -> str:
        for idx, entry in enumerate(self.cfg["questions"]):
            if Levenshtein.distance(question, entry["q"]) < 3:
                return self._expand(entry["a"], f"question{idx + 1}")
        raise RuntimeError(f"no matches for security question {repr(question)}")


class FTBSession:
    def __init__(self, cfg: Config, args):
        self.debug = args.debug
        opts = webdriver.FirefoxOptions()
        if not args.debug or args.force_headless:
            opts.add_argument("--headless")
        self.browser = webdriver.Firefox(opts)
        self.cfg = cfg

    def close(self):
        self.browser.close()

    def perform(self):
        try:
            log("access login page")
            self.browser.get(
                "https://webapp.ftb.ca.gov/MyFTBAccess/Login/AccessYourAccount"
            )
            self.browser.find_element(By.ID, "UserName").send_keys(self.cfg.username)
            self.browser.find_element(By.ID, "Password").send_keys(self.cfg.password)
            log("submit login page")
            self.browser.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
            time.sleep(5)
            log("wait for challenge validation")
            start_time = datetime.now()
            while True:
                if datetime.now() - start_time > timedelta(minutes=2):
                    raise RuntimeError("timed out waiting for akamai challenge")
                try:
                    if "Challenge Validation" in self.browser.page_source:
                        continue
                except Exception:
                    pass  # selenium race condition
                break
            time.sleep(3)
            assert (
                "You exceeded the allowed number of attempts"
                not in self.browser.page_source
            ), "got rate limited, need to wait 30 minutes and try again"
            assert (
                "The information you entered does not match our records"
                not in self.browser.page_source
            ), "wrong password, something is broken on our end most likely"
            if "verification code" in self.browser.page_source:
                assert (
                    self.debug
                ), "can't handle sms verification outside of debug mode, for now"
                log("wait for sms verification")
                while "verification code" in self.browser.page_source:
                    time.sleep(3)
                time.sleep(3)
            if "security question" in self.browser.page_source:
                log("submit security questions")
                question = self.browser.find_element(By.ID, "s_Answer_2").text
                answer = self.cfg.security_answer(question)
                self.browser.find_element(By.ID, "Answer").send_keys(answer)
                remember = self.browser.find_element(By.ID, "RememberMe")
                if not remember.is_selected():
                    remember.click()
                self.browser.find_element(
                    By.CSS_SELECTOR, "button[type='submit']"
                ).click()
                time.sleep(5)
            log("access password update page")
            self.browser.get(
                "https://webapp.ftb.ca.gov/MyFTBAccess/Profile/ChangePassword"
            )
            self.browser.find_element(By.ID, "OldPassword").send_keys(self.cfg.password)
            new_pass = pwgen(20)
            log("update password manager")
            self.cfg.password = new_pass
            log("submit password update page")
            self.browser.find_element(By.ID, "Password").send_keys(new_pass)
            self.browser.find_element(By.ID, "RePassword").send_keys(new_pass)
            self.browser.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
            time.sleep(5)
            assert (
                "You cannot change your password at this time"
                not in self.browser.page_source
            ), "system does not allow password changes right now, reason unclear"
            assert "Your information has been updated" in self.browser.page_source
            log("password changed successfully")
        except Exception:
            if self.debug:
                traceback.print_exc()
                import pdb

                pdb.set_trace()
            raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("--force-headless", action="store_true")
    parser.add_argument("profile")
    args = parser.parse_args()
    cfg = Config("ftb.yaml", args.profile)
    s = FTBSession(cfg, args=args)
    try:
        s.perform()
    finally:
        s.close()


if __name__ == "__main__":
    main()
    sys.exit(0)
