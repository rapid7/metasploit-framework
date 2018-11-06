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

  # == Dnsruby::SingleResolver
  # 
  #  This class has been deprecated.
  #  This implementation exists for legacy clients. New code should use the Dnsruby::Resolver class.
  #  The SingleResolver class targets a single resolver, and controls the sending of a single
  #  packet with a packet timeout. It performs no retries. Only two threads are used - the client
  #  thread and a select thread (which is reused across all queries).
  # 
  # == Methods
  # 
  # === Synchronous
  # These methods raise an exception or return a response message with rcode==NOERROR
  # 
  # *  Dnsruby::SingleResolver#send_message(msg [, use_tcp]))
  # *  Dnsruby::SingleResolver#query(name [, type [, klass]])
  # 
  # === Asynchronous
  # These methods use a response queue to return the response and the error to the client.
  # Support for EventMachine has been deprecated
  # 
  # *  Dnsruby::SingleResolver#send_async(...)
  # 
  class SingleResolver < Resolver
    #  Can take a hash with the following optional keys :
    # 
    #  * :server
    #  * :port
    #  * :use_tcp
    #  * :no_tcp
    #  * :ignore_truncation
    #  * :src_address
    #  * :src_address6
    #  * :src_port
    #  * :udp_size
    #  * :persistent_tcp
    #  * :persistent_udp
    #  * :tsig
    #  * :packet_timeout
    #  * :recurse
    def initialize(*args)
      arg=args[0]
      @single_res_mutex = Mutex.new
      @packet_timeout = Resolver::DefaultPacketTimeout
      @query_timeout = @packet_timeout
      @port = Resolver::DefaultPort
      @udp_size = Resolver::DefaultUDPSize
      @dnssec = Resolver::DefaultDnssec
      @use_tcp = false
      @no_tcp = false
      @tsig = nil
      @ignore_truncation = false
      @src_address        = nil
      @src_address6        = nil
      @src_port        = [0]
      @recurse = true
      @persistent_udp = false
      @persistent_tcp = false
      @retry_times = 1
      @retry_delay = 0
      @single_resolvers = []
      @configured = false
      @do_caching = true
      @config = Config.new

      if (arg==nil)
        #  Get default config
        @config = Config.new
        @config.get_ready
        @server = @config.nameserver[0]
      elsif (arg.kind_of?String)
        @config.get_ready
        @configured= true
        @config.nameserver=[arg]
        @server = @config.nameserver[0]
        #         @server=arg
      elsif (arg.kind_of?Name)
        @config.get_ready
        @configured= true
        @config.nameserver=arg
        @server = @config.nameserver[0]
        #         @server=arg
      elsif (arg.kind_of?Hash)
        arg.keys.each do |attr|
          if (attr == :server)
            @config.get_ready
            @configured= true
            @config.nameserver=[arg[attr]]
            @server = @config.nameserver[0]

          else
            begin
              send(attr.to_s+"=", arg[attr])
            rescue Exception
              Dnsruby.log.error{"Argument #{attr} not valid\n"}
            end
          end
        end
      end

      isr = PacketSender.new({:server=>@server, :port=>@port, :dnssec=>@dnssec,
          :use_tcp=>@use_tcp, :no_tcp=>@no_tcp, :packet_timeout=>@packet_timeout,
          :tsig => @tsig, :ignore_truncation=>@ignore_truncation,
          :src_address=>@src_address, :src_address6=>@src_address6, :src_port=>@src_port,
          :recurse=>@recurse, :udp_size=>@udp_size})

      @single_resolvers = [isr]

      #       ResolverRegister::register_single_resolver(self)
    end

    def server=(s)
      if (!@configured)
        @config.get_ready
      end
      @server = Config.resolve_server(s).to_s
      isr = PacketSender.new({:server=>@server, :dnssec=>@dnssec,
          :use_tcp=>@use_tcp, :no_tcp=>@no_tcp, :packet_timeout=>@packet_timeout,
          :tsig => @tsig, :ignore_truncation=>@ignore_truncation,
          :src_address=>@src_address, :src_address6=>@src_address6, :src_port=>@src_port,
          :recurse=>@recurse, :udp_size=>@udp_size})

      @single_res_mutex.synchronize {
        @single_resolvers = [isr]
      }
    end

    def server
      #       @single_res_mutex.synchronize {
      if (!@configured)
        @config.get_ready
        add_config_nameservers
      end
      return @single_resolvers[0].server
      #       }
    end

    def retry_times=(n) # :nodoc:
      raise NoMethodError.new("SingleResolver does not have retry_times")
    end
    def retry_delay=(n) # :nodoc:
      raise NoMethodError.new("SingleResolver does not have retry_delay")
    end

    def packet_timeout=(t)
      @packet_timeout = t
      @query_timeout = t
    end

    #  Add the appropriate EDNS OPT RR for the specified packet. This is done
    #  automatically, unless you are using Resolver#send_plain_message
    def add_opt_rr(m)
      @single_res_mutex.synchronize {
        @single_resolvers[0].add_opt_rr(m)
      }
    end

    alias :query_timeout :packet_timeout
    alias :query_timeout= :packet_timeout=
  end
end
