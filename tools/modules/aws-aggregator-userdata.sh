#!/bin/bash -ex

yum -y install ruby23 git
update-alternatives --set ruby /usr/bin/ruby2.3
git clone https://github.com/rapid7/metasploit-aggregator.git
cd metasploit-aggregator/ruby
gem install bundler
bundle
screen -d -m ruby -Ilib ./bin/metasploit-aggregator
