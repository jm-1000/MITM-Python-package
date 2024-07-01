#!/usr/bin/env python3

from setuptools import setup
from mitm import version

setup (
    name = "mitm",
    version = version,
    description = "Un paquet pour réaliser des attaques MITM (Man In The Middle)",
    packages = ["mitm"]
)