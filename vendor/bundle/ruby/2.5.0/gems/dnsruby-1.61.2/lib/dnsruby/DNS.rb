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
require 'dnsruby/hosts'
require 'dnsruby/config'
require "dnsruby/resolver"
module Dnsruby

  # == Dnsruby::DNS class
  # Resolv::DNS performs DNS queries.
  # 
  # === class methods
  # * Dnsruby::DNS.new(config_info=nil)
  # 
  #     ((|config_info|)) should be nil, a string or a hash.
  #     If nil is given, /etc/resolv.conf and platform specific information is used.
  #     If a string is given, it should be a filename which format is same as /etc/resolv.conf.
  #     If a hash is given, it may contains information for nameserver, search and ndots as follows.
  # 
  #       Dnsruby::DNS.new({:nameserver=>["210.251.121.21"], :search=>["ruby-lang.org"], :ndots=>1})
  # 
  # * Dnsruby::DNS.open(config_info=nil)
  # * Dnsruby::Resolv::DNS.open(config_info=nil) {|dns| ...}
  # 
  # === methods
  # * Dnsruby::DNS#close
  # 
  # * Dnsruby::DNS#getaddress(name)
  # * Dnsruby::DNS#getaddresses(name)
  # * Dnsruby::DNS#each_address(name) {|address| ...}
  #     address lookup methods.
  # 
  #     ((|name|)) must be an instance of Dnsruby::Name or String.  Resultant
  #     address is represented as an instance of Dnsruby::IPv4 or Dnsruby::IPv6.
  # 
  # * Dnsruby::DNS#getname(address)
  # * Dnsruby::DNS#getnames(address)
  # * Dnsruby::DNS#each_name(address) {|name| ...}
  #     These methods lookup hostnames .
  # 
  #     ((|address|)) must be an instance of Dnsruby::IPv4, Dnsruby::IPv6 or String.
  #     Resultant name is represented as an instance of Dnsruby::Name.
  # 
  # * Dnsruby::DNS#getresource(name, type, class)
  # * Dnsruby::DNS#getresources(name, type, class)
  # * Dnsruby::DNS#each_resource(name, type, class) {|resource| ...}
  #     These methods lookup DNS resources of ((|name|)).
  #     ((|name|)) must be a instance of Dnsruby::Name or String.
  # 
  #     ((|type|)) must be a member of Dnsruby::Types
  #     ((|class|)) must be a member of Dnsruby::Classes
  # 
  #     Resultant resource is represented as an instance of (a subclass of)
  #     Dnsruby::RR.
  #     (Dnsruby::RR::IN::A, etc.)
  # 
  # The searchlist and other Config info is applied to the domain name if appropriate. All the nameservers
  # are tried (if there is no timely answer from the first).
  # 
  # This class uses Resolver to perform the queries.
  # 
  # Information taken from the following places :
  # * STD0013
  # * RFC 1035, etc.
  # * ftp://ftp.isi.edu/in-notes/iana/assignments/dns-parameters
  # * etc.
  class DNS

    attr_accessor :do_caching

    # Creates a new DNS resolver. See Resolv::DNS.new for argument details.
    # 
    # Yields the created DNS resolver to the block, if given, otherwise returns it.
    def self.open(*args)
      dns = new(*args)
      return dns unless block_given?
      begin
        yield dns
      ensure
        dns.close
      end
    end

    # Closes the resolver
    def close
      @resolver.close
    end


    def to_s
      return "DNS : " + @config.to_s
    end

    # Creates a new DNS resolver
    # 
    # +config_info+ can be:
    # 
    # * nil:: Uses platform default (e.g. /etc/resolv.conf)
    # * String:: Path to a file using /etc/resolv.conf's format
    # * Hash:: Must contain :nameserver, :search and :ndots keys
    #    example :
    # 
    #     Dnsruby::DNS.new({:nameserver => ['210.251.121.21'],
    #                       :search => ['ruby-lang.org'],
    #                       :ndots => 1})
    def initialize(config_info=nil)
      @do_caching = true
      @config = Config.new()
      @config.set_config_info(config_info)
      @resolver = Resolver.new(@config)
#      if (@resolver.single_resolvers.length == 0)
#        raise ArgumentError.new("Must pass at least one valid resolver address")
#      end
    end

    attr_reader :config

    # Gets the first IP address of +name+ from the DNS resolver
    # 
    # +name+ can be a Dnsruby::Name or a String. Retrieved address will be a
    # Dnsruby::IPv4 or a Dnsruby::IPv6
    def getaddress(name)
      each_address(name) {|address| return address}
      raise ResolvError.new("DNS result has no information for #{name}")
    end

    # Gets all IP addresses of +name+ from the DNS resolver
    # 
    # +name+ can be a Dnsruby::Name or a String. Retrieved address will be a
    # Dnsruby::IPv4 or a Dnsruby::IPv6
    def getaddresses(name)
      ret = []
      each_address(name) {|address| ret << address}
      return ret
    end

    # Iterates over all IP addresses of +name+ retrieved from the DNS resolver
    # 
    # +name+ can be a Dnsruby::Name or a String. Retrieved address will be a
    # Dnsruby::IPv4 or a Dnsruby::IPv6
    def each_address(name)
      each_resource(name) {|resource| yield resource.address}
    end

    # Gets the first hostname for +address+ from the DNS resolver
    # 
    # +address+ must be a Dnsruby::IPv4, Dnsruby::IPv6 or a String. Retrieved
    # name will be a Dnsruby::Name.
    def getname(address)
      each_name(address) {|name| return name}
      raise ResolvError.new("DNS result has no information for #{address}")
    end

    # Gets all hostnames for +address+ from the DNS resolver
    # 
    # +address+ must be a Dnsruby::IPv4, Dnsruby::IPv6 or a String. Retrieved
    # name will be a Dnsruby::Name.
    def getnames(address)
      ret = []
      each_name(address) {|name| ret << name}
      return ret
    end

    # Iterates over all hostnames for +address+ retrieved from the DNS resolver
    # 
    # +address+ must be a Dnsruby::IPv4, Dnsruby::IPv6 or a String. Retrieved
    # name will be a Dnsruby::Name.
    def each_name(address)
      case address
      when Name
        ptr = address
      when  IPv4, IPv6
        ptr = address.to_name
      when IPv4::Regex
        ptr = IPv4.create(address).to_name
      when IPv6::Regex
        ptr = IPv6.create(address).to_name
      else
        raise ResolvError.new("cannot interpret as address: #{address}")
      end
      each_resource(ptr, Types.PTR, Classes.IN) {|resource| yield resource.domainname}
    end

    # Look up the first +type+, +klass+ resource for +name+
    # 
    # +type+ defaults to Dnsruby::Types.A
    # +klass+ defaults to Dnsruby::Classes.IN
    # 
    # Returned resource is represented as a Dnsruby::RR instance, e.g.
    # Dnsruby::RR::IN::A
    def getresource(name, type=Types.A, klass=Classes.IN)
      each_resource(name, type, klass) {|resource| return resource}
      raise ResolvError.new("DNS result has no information for #{name}")
    end

    # Look up all +type+, +klass+ resources for +name+
    # 
    # +type+ defaults to Dnsruby::Types.A
    # +klass+ defaults to Dnsruby::Classes.IN
    # 
    # Returned resource is represented as a Dnsruby::RR instance, e.g.
    # Dnsruby::RR::IN::A
    def getresources(name, type=Types.A, klass=Classes.IN)
      ret = []
      each_resource(name, type, klass) {|resource| ret << resource}
      return ret
    end

    # Iterates over all +type+, +klass+ resources for +name+
    # 
    # +type+ defaults to Dnsruby::Types.A
    # +klass+ defaults to Dnsruby::Classes.IN
    # 
    # Yielded resource is represented as a Dnsruby::RR instance, e.g.
    # Dnsruby::RR::IN::A
    def each_resource(name, type=Types.A, klass=Classes.IN, &proc)
      type = Types.new(type)
      klass = Classes.new(klass)
      reply, reply_name = send_query(name, type, klass)
      case reply.rcode.code
      when RCode::NOERROR
        extract_resources(reply, reply_name, type, klass, &proc)
        return
        #       when RCode::NXDomain
        #         Dnsruby.log.debug("RCode::NXDomain returned - raising error")
        #         raise Config::NXDomain.new(reply_name.to_s)
      else
        Dnsruby.log.error{"Unexpected rcode : #{reply.rcode.string}"}
        raise Config::OtherResolvError.new(reply_name.to_s)
      end
    end

    def extract_resources(msg, name, type, klass) # :nodoc:
      if type == Types.ANY
        n0 = Name.create(name)
        msg.each_answer {|rec|
          yield rec if n0 == rec.name
        }
      end
      yielded = false
      n0 = Name.create(name)
      msg.each_answer {|rec|
        if n0 == rec.name
          case rec.type
          when type
            if (rec.klass == klass)
              yield rec
              yielded = true
            end
          when Types.CNAME
            n0 = rec.domainname
          end
        end
      }
      return if yielded
      msg.each_answer {|rec|
        if n0 == rec.name
          case rec.type
          when type
            if (rec.klass == klass)
              yield rec
            end
          end
        end
      }
    end

    def send_query(name, type=Types.A, klass=Classes.IN) # :nodoc:
      candidates = @config.generate_candidates(name)
      exception = nil
      candidates.each do |candidate|
        q = Queue.new
        msg = Message.new
        msg.header.rd = 1
        msg.add_question(candidate, type, klass)
        msg.do_validation = false
        msg.header.cd = false
        msg.do_caching = do_caching
        @resolver.do_validation = false
        @resolver.send_async(msg, q)
        id, ret, exception = q.pop
        if (exception == nil && ret && ret.rcode == RCode.NOERROR)
          return ret, ret.question[0].qname
        end
      end
      raise exception
    end

  end
end
# --
# @TODO@ Asynchronous interface. Some sort of Deferrable?
# ++
