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

# e.g. ruby trace_dns.rb example.com

unless (1..2).include?(ARGV.length)
  puts "Usage: #{$0} domain [type]"
  exit(-1)
end


# Load DLV key
dlv_key = Dnsruby::RR.create("dlv.isc.org. IN DNSKEY 257 3 5 BEAAAAPHMu/5onzrEE7z1egmhg/WPO0+juoZrW3euWEn4MxDCE1+lLy2 brhQv5rN32RKtMzX6Mj70jdzeND4XknW58dnJNPCxn8+jAGl2FZLK8t+ 1uq4W+nnA3qO2+DL+k6BD4mewMLbIYFwe0PG73Te9fZ2kJb56dhgMde5 ymX4BI/oQ+cAK50/xvJv00Frf8kw6ucMTwFlgPe+jnGxPPEmHAte/URk Y62ZfkLoBAADLHQ9IrS2tryAe7mbBZVcOwIeU/Rw/mRx/vwwMCTgNboM QKtUdvNXDrYJDSHZws3xiRXF1Rf+al9UmZfSav/4NWLKjHzpT59k/VSt TDN0YUuWrBNh")
Dnsruby::Dnssec.add_dlv_key(dlv_key)

resolver = Dnsruby::Recursor.new
# TheLog.level = Logger::DEBUG


resolver.recursion_callback = Proc.new do |packet|
    packet.additional.each { |a| puts a }
    puts(";; Received #{packet.answersize} bytes from #{packet.answerfrom}. Security Level = #{packet.security_level.string}\n")
    puts "\n#{'-' * 79}\n"
end


domain = ARGV[0]
type = ARGV[1] || Types.A

begin
  response = resolver.query(domain, type)
  puts "\nRESPONSE : #{response}"
rescue Dnsruby::NXDomain
  puts "Domain '#{domain}' doesn't exist"
end
