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

# Example usage for Net::DNS::Resolver::Recurse
# Performs recursion for a query.

require 'dnsruby'

unless (1..3).include?(ARGV.length)
  puts "Usage: #{$0} domain [type [ class ]]"
  exit(-1)
end


resolver = Dnsruby::Recursor.new
resolver.hints = '198.41.0.4' # A.ROOT-SERVER.NET.


Dnsruby::TheLog.level = Logger::DEBUG


name, type, klass = ARGV
type  ||= 'A'
klass ||= 'IN'


packet = resolver.query(name, type, klass)
puts packet
