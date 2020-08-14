#!/bin/bash

if [ ! -e WebKit/WebKitBuild/Release ]; then
  svn checkout https://svn.webkit.org/repository/webkit/tags/Safari-608.5.11/ WebKit
  cd WebKit
  ./Tools/Scripts/set-webkit-configuration --release
  ./Tools/Scripts/build-webkit
fi
