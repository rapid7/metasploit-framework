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
# check_zone - Check a DNS zone for errors
# 
# = SYNOPSIS
# 
# check_zone [ -r ] <domain>
# 
# = DESCRIPTION
# 
# Checks a DNS zone for errors.  Current checks are:
# 
# * Checks that all A records have corresponding PTR records.
# 

# * Checks that hosts listed in NS, MX, and CNAME records have
# A records.
# 
# = OPTIONS
# 
# * -r Perform a recursive check on subdomains.
# 
# = AUTHOR
# 
# Michael Fuhr <mike@fuhr.org>
# (Ruby version AlexD, Nominet UK)
# 


def fatal_error(message)
  puts message
  exit(-1)
end

unless (1..2).include?(ARGV.length)
  fatal_error("Usage: #{$0}  domain [ class ]")
end


require 'dnsruby'
require 'getoptLong'


def check_domain(args)
  domain = args[0]
  klass = args[1] || 'IN'
  puts "----------------------------------------------------------------------"
  puts "#{domain} (class #{klass}\n"
  puts "----------------------------------------------------------------------"

  resolver = Dnsruby::Resolver.new
  resolver.retry_times = 2
  nspack = begin
    resolver.query(domain, 'NS', klass)
  rescue Exception => e
    print "Couldn't find nameservers for #{domain}: #{e}\n"
    return
  end

  print "nameservers (will request zone from first available):\n"
  ns_answers = nspack.answer.select {|r| r.type == 'NS' }
  ns_domain_names = ns_answers.map(&:domainname)
  ns_domain_names.each { |name| puts "\t#{name}" }
  puts ''

  resolver.nameserver = ns_domain_names

  zt = Dnsruby::ZoneTransfer.new
  zt.server = ns_domain_names

  zone = zt.transfer(domain) # , klass)
  unless zone
    fatal_error("Zone transfer failed: #{resolver.errorstring}")
  end

  puts "checking PTR records"
  check_ptr(domain, klass, zone)

  puts "\nchecking NS records"
  check_ns(domain, klass, zone)

  puts "\nchecking MX records"
  check_mx(domain, klass, zone)

  puts "\nchecking CNAME records"
  check_cname(domain, klass, zone)
  print "\n"

  if @recurse
    puts 'checking subdomains'
    subdomains = Hash.new
    #           foreach (grep { $_->type eq 'NS' and $_->name ne $domain } @zone) {
    zone.select { |i| i.type == 'NS' && i.name != domain }.each do |z|
      subdomains[z.name] = 1
    end
    #           foreach (sort keys %subdomains) {
    subdomains.keys.sort.each do |k|
      check_domain([k, klass])
    end
  end
end

def check_ptr(domain, klass, zone)
  resolver = Dnsruby::Resolver.new
  #   foreach $rr (grep { $_->type eq 'A' } @zone) {
  zone.select { |z| z.type == 'A' }.each do |rr|
    host = rr.name
    addr = rr.address
    ans = nil
    begin
      ans = resolver.query(addr.to_s, 'A') #, klass)
      puts "\t#{host} (#{addr}) has no PTR record" if ans.header.ancount < 1
    rescue Dnsruby::NXDomain
      puts "\t#{host} (#{addr}) returns NXDomain"
    end
  end
end

def check_ns(domain, klass, zone)
  resolver = Dnsruby::Resolver.new
  #   foreach $rr (grep { $_->type eq "NS" } @zone) {
  zone.select { |z| z.type == 'NS' }.each do |rr|
    ans = resolver.query(rr.nsdname, 'A', klass)
    puts "\t", rr.nsdname, ' has no A record' if (ans.header.ancount < 1)
  end
end

def check_mx(domain, klass, zone)
  resolver = Dnsruby::Resolver.new
  #   foreach $rr (grep { $_->type eq "MX" } @zone) {
  zone.select { |z| z.type == 'MX' }.each do |rr|
    ans = resolver.query(rr.exchange, 'A', klass)
    print "\t", rr.exchange, " has no A record\n" if (ans.header.ancount < 1)
  end
end

def check_cname(domain, klass, zone)
  resolver = Dnsruby::Resolver.new
  #   foreach $rr (grep { $_->type eq "CNAME" } @zone)
  zone.select { |z| z.type == 'CNAME' }.each do |rr|
    ans = resolver.query(rr.cname, 'A', klass)
    print "\t", rr.cname, " has no A record\n" if (ans.header.ancount < 1)
  end
end

def main
  opts = GetoptLong.new(['-r', GetoptLong::NO_ARGUMENT])
  @recurse = false
  opts.each do |opt, arg|
    case opt
    when '-r'
      @recurse = true
    end
  end

  check_domain(ARGV)
end


main
