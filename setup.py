#!/usr/bin/env python3

from setuptools import setup

setup(
    name='tp-connected',
    packages=['tp_connected'],
    version='0.0.2',
    install_requires=['aiohttp>=3.0.1','attrs'],
    description='TP-Link LTE modem API',
    author='Andrea Tosatto',
    url='https://github.com/andtos90/tp-connected',
    license='MIT',
    keywords=['tp-link,lte,MR6400'],
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3 :: Only",
    ],
)
