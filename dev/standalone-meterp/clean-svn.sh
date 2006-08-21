#!/bin/sh

find ./ -iname '*.ts.rb' -or -iname '*.ut.rb' -or -iname '.svn' -exec rm -rf {} \;
