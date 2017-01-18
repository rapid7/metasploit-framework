#!/usr/bin/env ruby
#
# $Id$
#
# This plugin provides management and interaction with an external session aggregator.
#
# $Revision$
#
require "msf/aggregator"

module Msf
  Aggregator_yaml = "#{Msf::Config.get_config_root}/aggregator.yaml" #location of the aggregator.yml containing saved aggregator creds
  Aggregator_Temp = "#{Msf::Config.get_config_root}/aggregator.temp"

class Plugin::Aggregator < Msf::Plugin
  class AggregatorCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    @response_queue = []

    def name
      "Aggregator"
    end

    def commands
      {
        'aggregator_connect'         => "Connect to a running Aggregator instance ( host[:port] )",
        'aggregator_save'            => "Save connection details to an Aggregator instance",
        'aggregator_disconnect'      => "Disconnect from an active Aggregator instance",
        'aggregator_addresses'       => "List all remote ip addresses available for ingress",
        'aggregator_cables'          => "List all remote listeners for sessions",
        'aggregator_cable_add'       => "Setup remote https listener for sessions",
        'aggregator_cable_remove'    => "Stop remote listener for sessions",
        'aggregator_default_forward' => "forward a unlisted/unhandled sessions to a specified listener",
        'aggregator_session_forward' => "forward a session to a specified listener",
        'aggregator_sessions'        => "List all remote sessions currently available from the Aggregator instance",
        'aggregator_session_park'    => "Park an existing session on the Aggregator instance",
        'aggregator_sysinfo'         => "Display detailed system information about the Aggregator instance",
      }
    end

    def aggregator_verify_db
      if ! (framework.db and framework.db.usable and framework.db.active)
        print_error("No database has been configured, please use db_create/db_connect first")
        return false
      end

      true
    end

    def aggregator_verify
      # return false if not aggregator_verify_db

      if ! @aggregator
        print_error("No active Aggregator instance has been configured, please use 'aggregator_connect'")
        return false
      end

      true
    end

    def usage(*lines)
      print_status("Usage: ")
      lines.each do |line|
        print_status("       #{line}")
      end
    end

    def usage_save
      usage("aggregator_save")
    end

    def usage_connect
      usage("aggregator_connect host[:port]",
            " -OR- ",
            "aggregator_connect host port")
    end

    def usage_cable_add
      usage('aggregator_cable_add host:port [certificate]',
            ' -OR- ',
            'aggregator_cable_add host port [certificate]')
    end

    def usage_cable_remove
      usage('aggregator_cable_remove host:port',
            ' -OR- ',
            'aggregator_cable_remove host port')
    end

    def usage_session_forward
      usage("aggregator_session_forward uri host:port",
            " -OR- ",
            "aggregator_session_forward uri host port")
    end

    def usage_default_forward
      usage("aggregator_session_forward host:port",
            " -OR- ",
            "aggregator_session_forward host port")
    end

    def cmd_aggregator_save(*args)
      #if we are logged in, save session details to aggregator.yaml
      if args[0] == "-h"
        usage_save
        return
      end

      if args[0]
        usage_save
        return
      end

      group = "default"

      if ((@host and @host.length > 0) and (@port and @port.length > 0 and @port.to_i > 0))
        config = {"#{group}" => {'server' => @host, 'port' => @port}}
        ::File.open("#{Aggregator_yaml}", "wb") { |f| f.puts YAML.dump(config) }
        print_good("#{Aggregator_yaml} created.")
      else
        print_error("Missing server/port - reconnect and then try again.")
        return
      end
    end

    def cmd_aggregator_connect(*args)
      # return if not aggregator_verify_db

      if ! args[0]
        if ::File.readable?("#{Aggregator_yaml}")
          lconfig = YAML.load_file("#{Aggregator_yaml}")
          @host = lconfig['default']['server']
          @port = lconfig['default']['port']
          aggregator_login
          return
        end
      end

      if(args.length == 0 or args[0].empty? or args[0] == "-h")
        usage_connect
        return
      end

      @host = @port = @sslv = nil

      case args.length
      when 1
        @host,@port = args[0].split(':', 2)
        @port ||= '2447'
      when 2
        @host,@port = args
      else
        usage_connect
        return
      end
      aggregator_login
    end

    def cmd_aggregator_sessions(*args)
      return if not aggregator_verify
      sessions_list = @aggregator.sessions
      unless sessions_list.nil?
        print_status("Sessions found:")
        sessions_list.each do |session|
          print_status("    #{session}")
        end
      end
    end

    def cmd_aggregator_addresses(*args)
      return if not aggregator_verify
      address_list = @aggregator.available_addresses
      unless address_list.nil?
        print_status("Remote addresses found:")
        address_list.each do |addr|
          print_status("    #{addr}")
        end
      end
    end

    def cmd_aggregator_cable_add(*args)
      return if not aggregator_verify
      host, port, certificate = nil
      case args.length
        when 1
          host, port = args[0].split(':', 2)
        when 2
          host, port = args[0].split(':', 2)
          if port.nil?
            port = args[1]
          else
            certificate = args[1]
          end
        when 3
          host, port, certificate = args
        else
          usage_cable_add
          return
      end
      if port.nil? || port.to_i <= 0
        usage_cable_add
      end
      if certificate && File.exists?(certificate)
        certificate = File.new(certificate).read
      end
      @aggregator.add_cable(Msf::Aggregator::Cable::HTTPS, host, port, certificate)
    end

    def cmd_aggregator_cables
      return if not aggregator_verify
      res = @aggregator.cables
      print_status("Remote Cables:")
      res.each do |k|
        print_status("    #{k}")
      end

    end

    def cmd_aggregator_cable_remove(*args)
      return if not aggregator_verify
      case args.length
        when 1
          host, port = args[0].split(':', 2)
        when 2
          host, port = args
      end
      if host.nil?
        usage_cable_remove
        return
      end
      @aggregator.remove_cable(host, port)
    end

    def cmd_aggregator_session_park(*args)
      return if not aggregator_verify
      case args.length
        when 1
          session_id = args[0]
          s = framework.sessions.get(session_id)
          unless s.nil?
            if @aggregator.sessions.keys.include? s.conn_id
              @aggregator.release_session(s.conn_id)
              framework.sessions.deregister(s)
            else
              # TODO: determine if we can add a transport and route with the aggregator
              # for now just report action not taken
              print_status("#{session_id} does not originate from the aggregator connection.")
            end
          else
            print_status("#{session_id} is not a valid session.")
          end
        else
          usage('aggregator_session_park session_id')
          return
      end
    end

    def cmd_aggregator_sysinfo(*args)
      return if not aggregator_verify

      res = { "wip" => "not implemented"}

      print_status("System Information")
      res.each_pair do |k,v|
        print_status("    #{k}: #{v}")
      end
    end

    def cmd_aggregator_default_forward(*args)
      return if not aggregator_verify
      @aggregator.register_default(@aggregator.uuid, nil)
    end

    def cmd_aggregator_session_forward(*args)
      return if not aggregator_verify
      session_uri = nil
      case args.length
        when 1
          session_uri = args[0]
        else
          usage_session_forward
          return
      end
      # TODO: call @aggregator.session and make sure session_uri is listed
      # TODO: ensure listener at host:port is open local if not start multi/handler universal
      @aggregator.obtain_session(session_uri, @aggregator.uuid)
    end

    def cmd_aggregator_disconnect(*args)
      if @aggregator && @aggregator.available?
        # check if this connection is the default forward
        @aggregator.register_default(nil, nil) if @aggregator.default == @aggregator.uuid

        # now check for any specifically forwarded sessions
        local_sessions_by_id = {}
        framework.sessions.each_pair do |id, s|
          local_sessions_by_id[s.conn_id] = s
        end

        sessions = @aggregator.sessions
        unless sessions.nil?
          sessions.each_pair do |session, console|
            next unless local_sessions_by_id.keys.include?(session)
            if console == @aggregator.uuid
               # park each session locally addressed
              cmd_aggregator_session_park(framework.sessions.key(local_sessions_by_id[session]))
            else
              # simple disconnect session that were from the default forward
              framework.sessions.deregister(local_sessions_by_id[session])
            end
          end
        end
      end
      @aggregator.stop if @aggregator
      if @payload_job_ids
        @payload_job_ids.each do |id|
          framework.jobs.stop_job(id)
        end
        @payload_job_ids = nil
      end
      @aggregator = nil
    end

    def aggregator_login

      if ! ((@host and @host.length > 0) and (@port and @port.length > 0 and @port.to_i > 0))
        usage_connect
        return
      end

      if(@host != "localhost" and @host != "127.0.0.1")
        print_error("Warning: SSL connections are not verified in this release, it is possible for an attacker")
        print_error("         with the ability to man-in-the-middle the Aggregator traffic to capture the Aggregator")
        print_error("         traffic, if you are running this on an untrusted network.")
        return
      end

      # Wrap this so a duplicate session does not prevent access
      begin
        cmd_aggregator_disconnect
      rescue ::Interrupt
        raise $!
      rescue ::Exception
      end

      begin
        print_status("Connecting to Aggregator instance at #{@host}:#{@port}...")
        @aggregator = Msf::Aggregator::ServerProxy.new(@host, @port)
      end

      aggregator_compatibility_check

      unless @payload_job_ids
        @payload_job_ids = []
        @my_io = get_local_handler
      end

      @aggregator.register_response_channel(@my_io)
      @aggregator
    end

    def aggregator_compatibility_check
      unless @aggregator.nil?
        unless @aggregator.available?
          print_error("Connection to aggregator @ #{@host}:#{@port} is unavailable.")
          cmd_aggregator_disconnect
        end
      end
    end

    def get_local_handler
      multi_handler = framework.exploits.create('multi/handler')

      multi_handler.datastore['LHOST']                = "127.0.0.1"
      # multi_handler.datastore['PAYLOAD']              = "multi/meterpreter/reverse_https"
      multi_handler.datastore['PAYLOAD']              = "multi/meterpreter/reverse_http"
      multi_handler.datastore['LPORT']                = "5000" # make this find a random local port

      # %w(DebugOptions PrependMigrate PrependMigrateProc
      #  InitialAutoRunScript AutoRunScript CAMPAIGN_ID HandlerSSLCert
      #  StagerVerifySSLCert PayloadUUIDTracking PayloadUUIDName
      #  IgnoreUnknownPayloads SessionRetryTotal SessionRetryWait
      #  SessionExpirationTimeout SessionCommunicationTimeout).each do |opt|
      #   multi_handler.datastore[opt] = datastore[opt] if datastore[opt]
      # end

      multi_handler.datastore['ExitOnSession'] = false
      multi_handler.datastore['EXITFUNC']      = 'thread'

      multi_handler.exploit_simple(
          'LocalInput' => nil,
          'LocalOutput' => nil,
          'Payload' => multi_handler.datastore['PAYLOAD'],
          'RunAsJob' => true
      )
      @payload_job_ids << multi_handler.job_id
      # requester = Msf::Aggregator::Http::SslRequester.new(multi_handler.datastore['LHOST'], multi_handler.datastore['LPORT'])
      requester = Msf::Aggregator::Http::Requester.new(multi_handler.datastore['LHOST'], multi_handler.datastore['LPORT'])
      requester
    end

    private :aggregator_login
    private :aggregator_compatibility_check
    private :aggregator_verify
    private :aggregator_verify_db
    private :get_local_handler
  end

  #
  # Plugin initialization
  #

  def initialize(framework, opts)
    super

    add_console_dispatcher(AggregatorCommandDispatcher)
    print_status("Aggregator interaction has been enabled")
  end

  def cleanup
    remove_console_dispatcher('Aggregator')
  end

  def name
    "aggregator"
  end

  def desc
    "Interacts with the external Session Aggregator"
  end
end
end
