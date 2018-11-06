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
module Dnsruby
# == Dnsruby::Hosts class
# Dnsruby::Hosts is a hostname resolver that uses the system hosts file
# 
# === class methods
# * Dnsruby::Hosts.new(hosts='/etc/hosts')
# 
# === methods
# * Dnsruby::Hosts#getaddress(name)
# * Dnsruby::Hosts#getaddresses(name)
# * Dnsruby::Hosts#each_address(name) {|address| ...}
#    address lookup methods.
# 
# * Dnsruby::Hosts#getname(address)
# * Dnsruby::Hosts#getnames(address)
# * Dnsruby::Hosts#each_name(address) {|name| ...}
#    hostnames lookup methods.
# 
  class Hosts
    if /mswin32|cygwin|mingw|bccwin/ =~ RUBY_PLATFORM
      require 'win32/resolv'
      DefaultFileName = Win32::Resolv.get_hosts_path
    else
      DefaultFileName = '/etc/hosts'
    end

    # Creates a new Dnsruby::Hosts using +filename+ for its data source
    def initialize(filename = DefaultFileName)
      @filename = filename
      @mutex = Mutex.new
      @initialized = nil
    end

    def lazy_initialize# :nodoc:
      @mutex.synchronize {
        unless @initialized
          @name2addr = {}
          @addr2name = {}
          begin
            open(@filename) {|f|
              f.each {|line|
                line.sub!(/#.*/, '')
                addr, hostname, *aliases = line.split(/\s+/)
                next unless addr
                addr.untaint
                hostname.untaint
                @addr2name[addr] = [] unless @addr2name.include? addr
                @addr2name[addr] << hostname
                @addr2name[addr] += aliases
                @name2addr[hostname] = [] unless @name2addr.include? hostname
                @name2addr[hostname] << addr
                aliases.each {|n|
                  n.untaint
                  @name2addr[n] = [] unless @name2addr.include? n
                  @name2addr[n] << addr
                }
              }
            }
          rescue Exception
            #  Java won't find this file if running on Windows
          end
          @name2addr.each {|name, arr| arr.reverse!}
          @initialized = true
        end
      }
      self
    end

    # Gets the first IP address for +name+ from the hosts file
    def getaddress(name)
      each_address(name) {|address| return address}
      raise ResolvError.new("#{@filename} has no name: #{name}")
    end

    # Gets all IP addresses for +name+ from the hosts file
    def getaddresses(name)
      ret = []
      each_address(name) {|address| ret << address}
      return ret
    end

    # Iterates over all IP addresses for +name+ retrieved from the hosts file
    def each_address(name, &proc)
      lazy_initialize
      if @name2addr.include?(name)
        @name2addr[name].each(&proc)
      end
    end

    # Gets the first hostname of +address+ from the hosts file
    def getname(address)
      each_name(address) {|name| return name}
      raise ResolvError.new("#{@filename} has no address: #{address}")
    end

    # Gets all hostnames for +address+ from the hosts file
    def getnames(address)
      ret = []
      each_name(address) {|name| ret << name}
      return ret
    end

    # Iterates over all hostnames for +address+ retrieved from the hosts file
    def each_name(address, &proc)
      lazy_initialize
      if @addr2name.include?(address)
        @addr2name[address].each(&proc)
      end
    end
  end
end