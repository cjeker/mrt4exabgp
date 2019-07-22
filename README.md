# Introduction

**mrt4exabgp** is a utility to convert MRT table dumps into exabgp announce
statements. Additionally it also reads and prints all API messages sent by
exabgp. The code was mostly ripped out of bgpctl(8) from OpenBGPD.

This tool can be used to emulate peers based on an MRT table dump.
See the *createconf.sh* script how this could be used.
