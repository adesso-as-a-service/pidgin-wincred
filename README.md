# pidgin-wincred

Pidgin usually stores passwords as plaintext, which is generally considered
a poor idea. This plugin uses the Windows Credential Manger to log passwords,
which in theory only allows the user who wrote the credentials to read
them back. Many would argue this is a more secure form of password storage.

This plugin has primarily been tested on Windows 7 and 10, but some users have
also reported success with Windows XP. Feedback would be helpful. Versions 0.7+
have only been tested on Windows 10 so far.

## Installation Instructions

Download the zip file for the latest version from the
[releases page](https://github.com/smarthouse/pidgin-wincred/releases).
Unzip the file, and copy the pidgin-wincred.dll file to the pidgin
plugin directly (usually ```%APPDATA%\.purple\plugins```).


## Build-it-yourself Instructions

To build the plugin from source manually, you will need to use the 32 bit
version of the mingw-w64 compiler and follow the instructions for [building
pidgin on windows](http://developer.pidgin.im/wiki/BuildingWinPidgin). The
easiest way to do this is to copy and paste from .travis.yml to set up your
build environment. The pidgin-wincred folder should be located in the pidgin
source folder. The pidgin source needs to be compiled first.
