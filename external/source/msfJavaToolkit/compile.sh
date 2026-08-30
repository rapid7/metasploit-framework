#!/bin/bash

# This requires Java 1.7 or earlier because it uses private APIs.
# See http://kris-sigur.blogspot.com/2014/10/heritrix-java-8-and-sunsecuritytoolskey.html
# for more information.

# Attempt to use Java 1.6 when building on OS X, otherwise JAVA_HOME needs to
# be set manually.
if [ -x /usr/libexec/java_home ]; then
  export JAVA_HOME=$(/usr/libexec/java_home -v 1.6)
fi

javac -classpath $JAVA_HOME/lib/tools.jar:. javaCompile/*.java

jar -cf msfJavaToolkit.jar javaCompile/*.class

mv msfJavaToolkit.jar ../../../data/exploits/
