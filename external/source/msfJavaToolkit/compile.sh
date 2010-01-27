#!/bin/bash

javac -classpath $JAVA_HOME/lib/tools.jar:. javaCompile/*.java sun/security/tools/*.java

jar -cf msfJavaToolkit.jar javaCompile/*.class sun/security/tools/*.class

mv msfJavaToolkit.jar ../../../data/exploits/
