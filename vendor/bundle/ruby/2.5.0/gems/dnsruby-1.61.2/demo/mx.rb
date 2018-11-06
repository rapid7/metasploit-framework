#! /usr/bin/env ruby

# --
# Copyright 2007 Nominet UK
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require 'dnsruby'

# = NAME
# 
# mx - Print a domain's MX records
# 
# = SYNOPSIS
# 
# mx domain
# 
# = DESCRIPTION
# 
# mx prints a domain's MX records, sorted by preference.
# 
# = AUTHOR
# 
# Michael Fuhr <mike@fuhr.org>
# (Ruby port AlexD, Nominet UK)
# 

def fatal_error(message)
  puts message
  exit -1
end


unless ARGV.length == 1
  fatal_error("Usage: #{$0} name")
end


domain = ARGV[0]
resolver = Dnsruby::DNS.new

begin
  resolver.each_resource(domain, 'MX') do |rr|
    print rr.preference, "\t", rr.exchange, "\n"
  end
rescue Exception => e
  fatal_error("Can't find MX hosts for #{domain}: #{e}")
end
