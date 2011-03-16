#!/bin/sh

javac -target 1.5 -source 1.5 AppletX.java
#javac AppletX.java
./get_offsets.rb AppletX.class
mv AppletX.class ../../../../data/exploits/cve-2010-4452/
rm -f AppletX.class
