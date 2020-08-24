#!/bin/bash

git clone https://github.com/bazad/threadexec.git
cd threadexec
git checkout 7c255d0a0d63464b82315d93a27dddc1d51b42d6
patch -p1 --forward < ../threadexec.diff
make
