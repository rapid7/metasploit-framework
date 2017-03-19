#!/bin/bash -ex

yum -y install ruby23
update-alternatives --set ruby /usr/bin/ruby2.3
gem install metasploit-aggregator
gem install bundler
cd /root
nohup /usr/local/bin/metasploit-aggregator &
