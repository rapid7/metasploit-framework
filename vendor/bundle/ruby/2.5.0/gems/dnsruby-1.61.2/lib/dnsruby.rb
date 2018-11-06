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
require 'dnsruby/code_mappers'
require 'dnsruby/message/message'
require 'dnsruby/ipv4'
require 'dnsruby/ipv6'
require 'timeout'
require 'dnsruby/the_log'
require 'dnsruby/version'
require 'dnsruby/cache'
require 'dnsruby/DNS'
require 'dnsruby/hosts'
require 'dnsruby/update'
require 'dnsruby/zone_transfer'
require 'dnsruby/dnssec'
require 'dnsruby/zone_reader'
require 'dnsruby/resolv'


# = Dnsruby library
# Dnsruby is a thread-aware DNS stub resolver library written in Ruby.
# 
# It is based on resolv.rb, the standard Ruby DNS implementation,
# but gives a complete DNS implementation, including DNSSEC.
# 
# The Resolv class can be used to resolve addresses using /etc/hosts and /etc/resolv.conf,
# or the DNS class can be used to make DNS queries. These interfaces will attempt to apply
# the default domain and searchlist when resolving names.
# 
# The Resolver and SingleResolver interfaces allow finer control of individual messages.
# The Resolver class sends queries to multiple resolvers using various retry mechanisms.
# The SingleResolver class is used by Resolver to send individual Messages to individual
# resolvers.
# 
# Resolver queries return Dnsruby::Message objects.  Message objects have five
# sections:
# 
# * The header section, a Dnsruby::Header object.
# 
# * The question section, a list of Dnsruby::Question objects.
# 
# * The answer section, a list of Dnsruby::Resource objects.
# 
# * The authority section, a list of Dnsruby::Resource objects.
# 
# * The additional section, a list of Dnsruby::Resource objects.
# 
# 
# == example
#  res = Dnsruby::Resolver.new # System default
#  ret = res.query("example.com")
#  print "#{ret.anwer.length} answer records returned, #{ret.answer.rrsets.length} RRSets returned in aswer section\n"
# 
#  p Dnsruby::Resolv.getaddress("www.ruby-lang.org")
#  p Dnsruby::Resolv.getname("210.251.121.214")
# 
#  Dnsruby::DNS.open {|dns|
#    p dns.getresources("www.ruby-lang.org", Dnsruby::Types.A).collect {|r| r.address}
#    p dns.getresources("ruby-lang.org", 'MX').collect {|r| [r.exchange.to_s, r.preference]}
#  }
# 
# == exceptions
# 
# * ResolvError < StandardError
# 
# * ResolvTimeout < Timeout::Error
# 
# * NXDomain < ResolvError
# 
# * FormErr < ResolvError
# 
# * ServFail < ResolvError
# 
# * NotImp < ResolvError
# 
# * Refused < ResolvError
# 
# * NotZone < ResolvError
# 
# * YXDomain < ResolvError
# 
# * YXRRSet < ResolvError
# 
# * NXRRSet < ResolvError
# 
# * NotAuth < ResolvError
# 
# * OtherResolvError < ResolvError
# 
# == I/O
# Dnsruby implements a pure Ruby event loop to perform I/O.
# Support for EventMachine has been deprecated.
# 
# == DNSSEC
# Dnsruby supports DNSSEC and NSEC(3).
# DNSSEC support is on by default - but no trust anchors are configured by default.
# See Dnsruby::Dnssec for more details.
# 
# == Codes
# Dnsruby makes extensive use of several different types of codes.  These are implemented
# in the form of subclasses of CodeMapper and are located in lib/code_mappers.rb.  They are:
# 
# * OpCode - e.g. Query, Status, Notify
# * RCode - e.g. NOERROR, NXDOMAIN
# * ExtendedRCode - currently only BADVERS
# * Classes - IN, CH, HS, NONE, ANY
# * Types - RR types, e.g. A, NS, SOA
# * QTypes - IXFR, AXFR, MAILB, MAILA, ANY
# * MetaTypes - TKEY, TSIG, OPT
# * Algorithms - e.g. RSAMD5, DH, DSA
# * Nsec3HashAlgorithms - currently only SHA-1

# == Bugs
# * NIS is not supported.
# * /etc/nsswitch.conf is not supported.
# * NSEC3 validation still TBD
module Dnsruby

  def Dnsruby.version
    return VERSION
  end

  @@logger = Logger.new(STDOUT)
  @@logger.level = Logger::FATAL
  # Get the log for Dnsruby
  # Use this to set the log level
  # e.g. Dnsruby.log.level = Logger::INFO
  def Dnsruby.log
    @@logger
  end


  #  Logs (error level) and raises an error.
  def log_and_raise(object, error_class = RuntimeError)
    if object.is_a?(Exception)
      error = object
      Dnsruby.log.error(error.inspect)
      raise error
    else
      message = object.to_s
      Dnsruby.log.error(message)
      raise error_class.new(message)
    end
  end; module_function :log_and_raise

  # An error raised while querying for a resource
  class ResolvError < StandardError
    attr_accessor :response
  end

  # A timeout error raised while querying for a resource
  class ResolvTimeout < Timeout::Error
  end

  # The requested domain does not exist
  class NXDomain < ResolvError
  end

  # A format error in a received DNS message
  class FormErr < ResolvError
  end

  # Indicates a failure in the remote resolver
  class ServFail < ResolvError
  end

  # The requested operation is not implemented in the remote resolver
  class NotImp < ResolvError
  end

  # The requested operation was refused by the remote resolver
  class Refused < ResolvError
  end

  # The update RR is outside the zone (in dynamic update)
  class NotZone < ResolvError
  end

  # Some name that ought to exist, does not exist (in dynamic update)
  class YXDomain < ResolvError
  end

  # Some RRSet that ought to exist, does not exist (in dynamic update)
  class YXRRSet < ResolvError
  end

  # Some RRSet that ought not to exist, does exist (in dynamic update)
  class NXRRSet < ResolvError
  end

  # The nameserver is not responsible for the zone (in dynamic update)
  class NotAuth < ResolvError
  end


  # Another kind of resolver error has occurred
  class OtherResolvError < ResolvError
  end

  # Socket was closed by server before request was processed
  class SocketEofResolvError < ResolvError
  end

  # An error occurred processing the TSIG
  class TsigError < OtherResolvError
  end

  #  Sent a signed packet, got an unsigned response
  class TsigNotSignedResponseError < TsigError
  end

  # Indicates an error in decoding an incoming DNS message
  class DecodeError < ResolvError
    attr_accessor :partial_message
  end

  # Indicates an error encoding a DNS message for transmission
  class EncodeError < ResolvError
  end

  # Indicates an error verifying
  class VerifyError < ResolvError
  end

  # Indicates a zone transfer has failed due to SOA serial mismatch
  class ZoneSerialError < ResolvError
  end
end
