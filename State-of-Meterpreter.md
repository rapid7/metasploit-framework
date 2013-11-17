In recent months a number of changes have been made to the [Meterpreter](https://github.com/rapid7/meterpreter) source. These changes have not only improved Meterpreter's stability and feature-set, they also bring it into the modern world of C and C++ development on Windows using tools that are free to download and easy to set up.

Meterpreter is no longer difficult to compile and is now in a state where contributors from the Open Source community should be able to add their features without the tools and environment getting in the way. A single `make` command is all that's required.

As of [Commit 3bdaa50bfe49850903dae94f2937fca4fa7287d5](https://github.com/rapid7/meterpreter/commit/3bdaa50bfe49850903dae94f2937fca4fa7287d5) Windows Meterpreter builds _cleanly_ with `0` Errors and `0` Warnings, and this is how it will stay.

So go and clone the [Meterpreter repository](https://github.com/rapid7/meterpreter) and get cracking. The build instructions are listed in the [Meterpreter README](https://github.com/rapid7/meterpreter/blob/master/README.md).