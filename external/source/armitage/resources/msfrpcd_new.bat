@echo off
set BASE=$$BASE$$..\..\
cd "%BASE%"
set PATH=%BASE%ruby\bin;%BASE%java\bin;%BASE%tools;%BASE%nmap;%BASE%postgresql\bin;%PATH%
IF NOT EXIST "%BASE%java" GOTO NO_JAVA
set JAVA_HOME="%BASE%java"
:NO_JAVA
set MSF_DATABASE_CONFIG="%BASE%apps\pro\ui\config\database.yml"
set MSF_BUNDLE_GEMS=0
set BUNDLE_GEMFILE=%BASE%apps\pro\ui\Gemfile
cd "%BASE%apps\pro\msf3"
rubyw msfrpcd -a 127.0.0.1 -U $$USER$$ -P $$PASS$$ -S -f -p $$PORT$$
