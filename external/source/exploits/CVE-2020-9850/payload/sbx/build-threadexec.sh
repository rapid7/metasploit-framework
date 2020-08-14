#!/bin/bash

git clone https://github.com/bazad/threadexec.git
cd threadexec
patch -p1 --forward < ../threadexec.diff
make
