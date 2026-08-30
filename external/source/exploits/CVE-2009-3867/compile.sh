#!/bin/sh

javac -target 1.3 -source 1.3 AppletX.java

jar cvf CVE-2009-3867.jar AppletX.class
rm -f AppletX.class

mv CVE-2009-3867.jar ../../../../data/exploits/CVE-2009-3867.jar
