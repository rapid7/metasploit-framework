# -*- coding: binary -*-
require 'msf/core/exploit'
module Msf
  ###
  #
  # This module provides methods for working with redis
  #
  ###
  module Auxiliary::Redis
    include Msf::Exploit::Remote::Tcp
    include Auxiliary::Scanner
    include Auxiliary::Report

    #
    # Initializes an instance of an auxiliary module that interacts with Redis
    #

    def initialize(info = {})
      super
      register_options(
        [
          Opt::RPORT(6379)
        ]
      )

      register_advanced_options(
        [
          OptInt.new('READ_TIMEOUT', [true, 'Seconds to wait while reading redis responses', 2])
        ]
      )
    end

    def peer
      "#{rhost}:#{rport}"
    end

    def read_timeout
      datastore['READ_TIMEOUT']
    end

    def redis_auth?(password)
      # Request for authentication in a password-protected Redis server.
      # Redis can be instructed to require a password before allowing clients to
      # execute commands. This is done using requirepass directive in the
      # configuration file.
      #
      # If password matches the password in the configuration file, the server
      # replies with the OK status code and starts accepting commands.
      data = send_redis_command('AUTH', password)
      data && data.include?('+OK') ? true : false
    end

    def redis_proto(commands)
      return if commands.blank?
      command = "*#{commands.length}\r\n"
      commands.each do |c|
        command << "$#{c.length}\r\n#{c}\r\n"
      end
      command
    end

    def report_redis(version)
      report_service(
        host: rhost,
        port: rport,
        proto: 'tcp',
        name: 'redis',
        info: "version #{version}"
      )
    end

    def send_redis_command(*commands)
      sock.put(redis_proto(commands))
      data = sock.get_once(-1, read_timeout)
      return unless data
      data.strip!
      vprint_status("#{peer} -- redis command '#{Rex::Text.ascii_safe_hex(commands.join(' '), true)}' got '#{Rex::Text.ascii_safe_hex(data, true)}'")
      data
    end
  end
end
