# Introduction

This module allows you to generate a Windows EXE that evades against Microsoft Windows Defender.
To achieve this, multiple techniques are used:

## Shellcode encryption

RC4 is used to prevent the shellcode from getting caught by static scanning.

## Custom Compiler

A custom compiler is also used with evasion in mind. This compiler can keep the EXE randomized,
also harder to reverse-engineer with typical tools.

## Anti-Emulation

An anti-emulation technique is used to prevent the shellcode from being analyzed at run-time.
Technically, this is taking advantage of a weakness in Windows Defender's scan engine
(an artifact,a poor design, etc), so every once a while this part may be tweaked to keep up with
Microsoft updates.

## Traffic Encryption

Some Meterpreters support encryption, such as RC4 or HTTPS. You either should consider using a
custom payload of your own to avoid detection, or at least use one that supports encryption for
best results.

# Demonstration

The following demonstrates how to generate a payload with windows_defender_exe, and successfully
evades Windows Defender:

![alt text](https://user-images.githubusercontent.com/1170914/45052465-7e6ee500-b04c-11e8-90e0-e9c59363bb45.gif)