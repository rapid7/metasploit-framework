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
# check_soa - Check a domain's nameservers
# 
# = SYNOPSIS
# 
# check_soa domain
# 
# = DESCRIPTION
# 
# check_soa queries each of a domain's nameservers for the Start
# of Authority (SOA) record and prints the serial number.  Errors
# are printed for nameservers that couldn't be reached or didn't
# answer authoritatively.
# 
# = AUTHOR
# 
# The original Bourne Shell and C versions were printed in
# "DNS and BIND" by Paul Albitz & Cricket Liu.
# 
# The Perl version was written by Michael Fuhr <mike@fuhr.org>.
# 
# = SEE ALSO
# 
# axfr, check_zone, mresolv, mx, perldig, Net::DNS

require 'dnsruby'

NO_DOMAIN_SPECIFIED = -1
NO_NAMESERVERS      = -2


def fatal_error(message, exit_code)
  puts message
  exit(exit_code)
end


def usage
  fatal_error("Usage: #{$0} domain", NO_DOMAIN_SPECIFIED)
end


def create_resolver
  resolver = Dnsruby::Resolver.new
  resolver.retry_times = 2
  resolver.recurse = 0  # Send out non-recursive queries
  # disable caching otherwise SOA is cached from first nameserver queried
  resolver.do_caching = false
  resolver
end


def get_ns_response(resolver, domain)
  ns_response = resolver.query(domain, 'NS')
  if ns_response.header.ancount == 0
    fatal_error("No nameservers found for #{domain}.", NO_NAMESERVERS)
  end
  ns_response
end


# Finds all the nameserver domains for the domain.
def get_ns_domains(resolver, domain)
  ns_response = get_ns_response(resolver, domain)
  ns_answers = ns_response.answer.select { |r| r.type == 'NS'}
  ns_answers.map(&:domainname)
end


def process_ns_domain(resolver, domain, ns_domain)

  a_response = begin
    #  In order to lookup the IP(s) of the nameserver, we need a Resolver
    #  object that is set to our local, recursive nameserver.  So we create
    #  a new object just to do that.
    local_resolver = Dnsruby::Resolver.new

    local_resolver.query(ns_domain, 'A')
  rescue Exception => e
    puts "Cannot find address for #{ns_domain}: #{e}"
    return
  end

  a_answers = a_response.answer.select {|r| r.type == 'A'}
  a_answers.each do |a_answer|

    # ----------------------------------------------------------------------
    #  Ask this IP.
    # ----------------------------------------------------------------------
    ip_address = a_answer.address
    resolver.nameserver = ip_address.to_s
    print "#{ns_domain} (#{ip_address}): "

    # ----------------------------------------------------------------------
    #  Get the SOA record.
    # ----------------------------------------------------------------------
    soa_response = begin
      resolver.query(domain, 'SOA', 'IN')
    rescue Exception => e
      puts "Error : #{e}"
      return
    end

    # ----------------------------------------------------------------------
    #  Is this nameserver authoritative for the domain?
    # ----------------------------------------------------------------------

    unless soa_response.header.aa
      print "isn't authoritative for #{domain}\n"
      return
    end

    # ----------------------------------------------------------------------
    #  We should have received exactly one answer.
    # ----------------------------------------------------------------------

    unless soa_response.header.ancount == 1
      puts "expected 1 answer, got #{soa_response.header.ancount}."
      return
    end

    # ----------------------------------------------------------------------
    #  Did we receive an SOA record?
    # ----------------------------------------------------------------------

    answer_type = soa_response.answer[0].type
    unless answer_type == 'SOA'
      puts "expected SOA, got #{answer_type}"
      return
    end

    # ----------------------------------------------------------------------
    #  Print the serial number.
    # ----------------------------------------------------------------------

    puts "has serial number #{soa_response.answer[0].serial}"
  end
end


def main

  # Get domain from command line, printing usage and exiting if none provided:
  domain = ARGV.fetch(0) { usage }

  resolver = create_resolver

  ns_domains = get_ns_domains(resolver, domain)

  # ------------------------------------------------------------------------------
  #  Check the SOA record on each nameserver.
  # ------------------------------------------------------------------------------
  ns_domains.each do |ns_domain_name|
    process_ns_domain(resolver, domain, ns_domain_name)
  end
end


main
