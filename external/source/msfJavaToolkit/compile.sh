#!/bin/bash

javac -classpath $JAVA_HOME/lib/tools.jar:. javaCompile/*.java

jar -cf msfJavaToolkit.jar javaCompile/*.class

mv msfJavaToolkit.jar ../../../data/exploits/
