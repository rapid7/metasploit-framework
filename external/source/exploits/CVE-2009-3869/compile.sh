#!/bin/sh

javac -target 1.3 -source 1.3 AppletX.java

jar cvf CVE-2009-3869.jar AppletX.class BoomFilter.class test.png
rm -f AppletX.class BoomFilter.class

mv CVE-2009-3869.jar ../../../../data/exploits/CVE-2009-3869.jar
