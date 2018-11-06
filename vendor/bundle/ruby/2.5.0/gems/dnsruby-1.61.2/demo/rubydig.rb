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

# = NAME
# 
# rubydig - Ruby script to perform DNS queries
# 
# = SYNOPSIS
# 
# rubydig [ @nameserver ] name [ type [ class ] ]
# 
# = DESCRIPTION
# 
# Performs a DNS query on the given name.  The record type
# and class can also be specified; if left blank they default
# to A and IN.
# 
# = AUTHOR
# 
# Michael Fuhr <mike@fuhr.org>
# 

def fatal_error(message)
  puts message
  exit(-1)
end


unless (1..3).include?(ARGV.length)
  fatal_error("Usage: #{$0} [ @nameserver ] name [ type [ class ] ]")
end


require 'dnsruby'


resolver = Dnsruby::Resolver.new
zone_transfer = Dnsruby::ZoneTransfer.new


if ARGV[0] =~ /^@/
  nameserver = ARGV.shift
  if nameserver == '@auth'
    resolver = Dnsruby::Recursor.new
  else
    puts "Setting nameserver : #{nameserver}"
    resolver.nameserver = (nameserver.sub(/^@/, ''))
    puts "nameservers = #{resolver.config.nameserver}"
    zone_transfer.server = (nameserver.sub(/^@/, ''))
  end
end

name, type, klass = ARGV
type  ||= 'A'
klass ||= 'IN'

if type.upcase == 'AXFR'
  rrs = zone_transfer.transfer(name) # , klass)

  if rrs
    rrs.each { |rr| puts rr }
  else
    fatal_error("Zone transfer failed: #{resolver.errorstring}")
  end

else

#    Dnsruby::TheLog.level=Logger::DEBUG
  begin
    answer = resolver.query(name, type, klass)
    puts answer
  rescue Exception => e
    fatal_error("Query failed: #{e}")
  end
end
