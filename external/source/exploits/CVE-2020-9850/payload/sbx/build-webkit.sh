#!/bin/bash

if [ ! -e WebKit ]; then
    svn checkout -r 254377 --depth empty https://svn.webkit.org/repository/webkit/tags/Safari-608.5.11/Source/ WebKit/Source
    cd WebKit/Source
    svn update --set-depth empty WebCore WebCore/platform
    svn update --set-depth infinity WebCore/platform/network WTF
fi

