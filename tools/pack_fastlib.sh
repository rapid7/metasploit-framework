#!/bin/sh

mkdir fastlib-archived
./lib/fastlib.rb store modules.fastlib 12345603 modules/ modules/*
./lib/fastlib.rb store lib/metasploit.fastlib 12345603 lib lib/msf/ lib/rex*
mv lib/msf lib/rex* modules/ fastlib-archived
