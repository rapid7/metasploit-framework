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

require_relative 'spec_helper'
Dnsruby.log.level = Logger::FATAL

require 'socket'


# Tells whether or not we can connect to the Internet.
def online?
  sock = UDPSocket.new()
  online = false
  begin
    sock.connect('193.0.14.129', 25) # that address is k.root-servers.net
    online = true
    sock.close
  rescue Exception => exception
    puts "
------------------------------------------------------------
Cannot bind to socket:
        #{exception}

This is an indication you have network problems.
No online tests will be run!!
------------------------------------------------------------
"
  end
  online
end


if online?
  online_tests = %w(
      axfr
      hs
      recur
      resolv
      resolver
      tcp
      tcp_pipelining
      single_resolver
      cache
      dns
      rr-opt
      res_config
  )


  # Excluded are:
  #
  # inet6
  # recurse
  # queue
  # soak

  #    OK - online and ready to go
  puts '
Running online tests. These tests send UDP packets - some may be lost.
If you get the odd timeout error with these tests, try running them again.
It may just be that some UDP packets got lost the first time...
'

  online_tests.each { |test| require_relative("tc_#{test}.rb") }
end


# We have set server_up to unconditionally return false.
# Therefore, to avoid any misconception that this code could run,
# I'm commenting it out.
=begin
def server_up?
  false
#  Check if we can contact the server - if we can't, then abort the test
  #  (but tell user that test has not been run due to connectivity problems)

  #  Disabling the attempt to connect to Nominet servers...
  #  begin
  #    sock = UDPSocket.new
  #    sock.connect('ns0.validation-test-servers.nominet.org.uk',
  #      25)
  #    sock.close
  #    server_up = true
  #  rescue Exception
  #    puts "----------------------------------------"
  #    puts "Cannot connect to test server\n\t"+$!.to_s+"\n"
  #    puts "\n\nNo tests targetting this server will be run!!\n\n"
  #    puts "----------------------------------------"
  #  end
end


if (server_up)

  require_relative "tc_single_resolver.rb"
  require_relative "tc_cache.rb"
  require_relative "tc_dns.rb"
  require_relative "tc_rr-opt.rb"
  require_relative "tc_res_config.rb"

  have_openssl = false
  begin
    require "openssl"
    OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, "key", "data")
    key = OpenSSL::PKey::RSA.new
    key.e = 111

    have_openssl=true
  rescue Exception => e
    puts "-------------------------------------------------------------------------"
    puts "OpenSSL not present (with full functionality) - skipping TSIG/DNSSEC test"
    puts "-------------------------------------------------------------------------"
  end
  if (have_openssl)
    require_relative "tc_tsig.rb"
    puts "------------------------------------------------------"
    puts "Running DNSSEC test - may fail if OpenSSL not complete"
    puts "------------------------------------------------------"
    require_relative "tc_verifier.rb"
    require_relative "tc_dlv.rb"
    require_relative "tc_validator.rb"
  end
=end

#    have_em = false
#    begin
#      require 'eventmachine'
#      have_em = true
#    rescue LoadError => e
#      puts "----------------------------------------"
#      puts "EventMachine not installed - skipping test"
#      puts "----------------------------------------"
#    end
#    if (have_em)
#      require 'test/tc_event_machine_single_res.rb'
#      require 'test/tc_event_machine_res.rb'
#      require 'test/tc_event_machine_deferrable.rb'
#    end
