#
# $Id$
#
# This plugin provides management and interaction with an external session aggregator.
#
# $Revision$
#

module Msf
  Aggregator_yaml = "#{Msf::Config.get_config_root}/aggregator.yaml" # location of the aggregator.yml containing saved aggregator creds

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
          'aggregator_sessions'        => "List all remote sessions currently available from the Aggregator instance",
          'aggregator_session_forward' => "forward a session to a specified listener",
          'aggregator_session_park'    => "Park an existing session on the Aggregator instance"
        }
      end

      def aggregator_verify
        if !@aggregator
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
        usage("aggregator_session_forward remote_id")
      end

      def usage_default_forward
        usage("aggregator_session_forward")
      end

      def show_session(details, target, local_id)
        status = pad_space("  #{local_id}", 4)
        status += "  #{details['ID']}"
        status = pad_space(status, 15)
        status += "  meterpreter "
        status += "#{guess_target_platform(details['OS'])} "
        status = pad_space(status, 43)
        status += "#{details['USER']} @ #{details['HOSTNAME']} "
        status = pad_space(status, 64)
        status += "#{details['LOCAL_SOCKET']} -> #{details['REMOTE_SOCKET']}"
        print_status status
      end

      def show_session_detailed(details, target, local_id)
        print_status "\t Remote ID: #{details['ID']}"
        print_status "\t      Type: meterpreter #{guess_target_platform(details['OS'])}"
        print_status "\t      Info: #{details['USER']} @ #{details['HOSTNAME']}"
        print_status "\t    Tunnel: #{details['LOCAL_SOCKET']} -> #{details['REMOTE_SOCKET']}"
        print_status "\t       Via: exploit/multi/handler"
        print_status "\t      UUID: #{details['UUID']}"
        print_status "\t MachineID: #{details['MachineID']}"
        print_status "\t   CheckIn: #{details['LAST_SEEN'].to_i}s ago" unless details['LAST_SEEN'].nil?
        print_status "\tRegistered: Not Yet Implemented"
        print_status "\t   Forward: #{target}"
        print_status "\tSession ID: #{local_id}" unless local_id.nil?
        print_status ""
      end

      def cmd_aggregator_save(*args)
        # if we are logged in, save session details to aggregator.yaml
        if args.length > 0 || args[0] == "-h"
          usage_save
          return
        end

        if args[0]
          usage_save
          return
        end

        group = "default"

        if (@host && @host.length > 0) && (@port && @port.length > 0 && @port.to_i > 0)
          config = { "#{group}" => { 'server' => @host, 'port' => @port } }
          ::File.open("#{Aggregator_yaml}", "wb") { |f| f.puts YAML.dump(config) }
          print_good("#{Aggregator_yaml} created.")
        else
          print_error("Missing server/port - reconnect and then try again.")
          return
        end
      end

      def cmd_aggregator_connect(*args)
        if !args[0]
          if ::File.readable?("#{Aggregator_yaml}")
            lconfig = YAML.load_file("#{Aggregator_yaml}")
            @host = lconfig['default']['server']
            @port = lconfig['default']['port']
            aggregator_login
            return
          end
        end

        if args.length == 0 || args[0].empty? || args[0] == "-h"
          usage_connect
          return
        end

        @host = @port = @sslv = nil

        case args.length
        when 1
          @host, @port = args[0].split(':', 2)
          @port ||= '2447'
        when 2
          @host, @port = args
        else
          usage_connect
          return
        end
        aggregator_login
      end

      def cmd_aggregator_sessions(*args)
        case args.length
          when 0
            isDetailed = false
          when 1
            unless args[0] == "-v"
              usage_sessions
              return
            end
            isDetailed = true
          else
            usage_sessions
            return
        end
        return unless aggregator_verify

        sessions_list = @aggregator.sessions
        return if sessions_list.nil?

        session_map = {}

        # get details for each session and print in format of sessions -v
        sessions_list.each do |session|
          session_id, target = session
          details = @aggregator.session_details(session_id)
          local_id = nil
          framework.sessions.each_pair do |key, value|
            next unless value.conn_id == session_id
            local_id = key
          end
          # filter session that do not have details as forwarding options (this may change later)
          next unless details && details['ID']
          session_map[details['ID']] = [details, target, local_id]
        end

        print_status("Remote sessions")
        print_status("===============")
        print_status("")
        if session_map.length == 0
          print_status("No remote sessions.")
        else
          unless isDetailed
            print_status("  Id  Remote Id  Type                      Information          Connection")
            print_status("  --  ---------  ----                      -----------          ----------")
          end
          session_map.keys.sort.each do |key|
            details, target, local_id = session_map[key]
            unless isDetailed
              show_session(details, target, local_id)
            else
              show_session_detailed(details, target, local_id)
            end
          end
        end
      end

      def cmd_aggregator_addresses(*_args)
        return if !aggregator_verify

        address_list = @aggregator.available_addresses
        return if address_list.nil?

        print_status("Remote addresses found:")
        address_list.each do |addr|
          print_status("    #{addr}")
        end
      end

      def cmd_aggregator_cable_add(*args)
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

        if !aggregator_verify || args.length == 0 || args[0] == '-h' || \
            port.nil? || port.to_i <= 0
          usage_cable_add
          return
        end

        certificate = File.new(certificate).read if certificate && File.exists?(certificate)

        @aggregator.add_cable(Metasploit::Aggregator::Cable::HTTPS, host, port, certificate)
      end

      def cmd_aggregator_cables(*_args)
        return if !aggregator_verify
        res = @aggregator.cables
        print_status("Remote Cables:")
        res.each do |k|
          print_status("    #{k}")
        end

      end

      def cmd_aggregator_cable_remove(*args)
        case args.length
          when 1
            host, port = args[0].split(':', 2)
          when 2
            host, port = args
        end
        if !aggregator_verify || args.length == 0 || args[0] == '-h' || host.nil?
          usage_cable_remove
          return
        end
        @aggregator.remove_cable(host, port)
      end

      def cmd_aggregator_session_park(*args)
        return if !aggregator_verify

        case args.length
          when 1
            session_id = args[0]
            s = framework.sessions.get(session_id)
            unless s.nil?
              if @aggregator.sessions.keys.include? s.conn_id
                @aggregator.release_session(s.conn_id)
                framework.sessions.deregister(s)
              else
                # TODO: determine if we can add a transport and route with the
                # aggregator. For now, just report action not taken.
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

      def cmd_aggregator_default_forward(*_args)
        return if !aggregator_verify

        @aggregator.register_default(@aggregator.uuid, nil)
      end

      def cmd_aggregator_session_forward(*args)
        return if !aggregator_verify

        remote_id = nil
        case args.length
          when 1
            remote_id = args[0]
          else
            usage_session_forward
            return
        end
        # find session with ID matching request
        @aggregator.sessions.each do |session|
          session_uri, _target = session
          details = @aggregator.session_details(session_uri)
          next unless details['ID'] == remote_id
            return @aggregator.obtain_session(session_uri, @aggregator.uuid)
        end
        print_error("#{remote_id} was not found.")
      end

      def cmd_aggregator_disconnect(*_args)
        if @aggregator && @aggregator.available?
          # check if this connection is the default forward
          @aggregator.register_default(nil, nil) if @aggregator.default == @aggregator.uuid

          # now check for any specifically forwarded sessions
          local_sessions_by_id = {}
          framework.sessions.each_pair do |_id, s|
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

        if !((@host && @host.length > 0) && (@port && @port.length > 0 && @port.to_i > 0))
          usage_connect
          return
        end

        if @host != "localhost" and @host != "127.0.0.1"
          print_error("Warning: SSL connections are not verified in this release, it is possible for an attacker")
          print_error("         with the ability to man-in-the-middle the Aggregator traffic to capture the Aggregator")
          print_error("         traffic, if you are running this on an untrusted network.")
          return
        end

        # Wrap this so a duplicate session does not prevent access
        begin
          cmd_aggregator_disconnect
        rescue ::Interrupt => i
          raise i
        rescue ::Exception
        end

        begin
          print_status("Connecting to Aggregator instance at #{@host}:#{@port}...")
          @aggregator = Metasploit::Aggregator::ServerProxy.new(@host, @port)
        end

        aggregator_compatibility_check

        unless @payload_job_ids
          @payload_job_ids = []
          @my_io = local_handler
        end

        @aggregator.register_response_channel(@my_io)
        @aggregator
      end

      def aggregator_compatibility_check
        false if @aggregator.nil?
        unless @aggregator.available?
          print_error("Connection to aggregator @ #{@host}:#{@port} is unavailable.")
          cmd_aggregator_disconnect
        end
      end

      def local_handler
        # get a random ephemeral port
        server = TCPServer.new('127.0.0.1', 0)
        port = server.addr[1]
        server.close

        multi_handler = framework.exploits.create('multi/handler')

        multi_handler.datastore['LHOST']                = "127.0.0.1"
        # multi_handler.datastore['PAYLOAD']              = "multi/meterpreter/reverse_https"
        multi_handler.datastore['PAYLOAD']              = "multi/meterpreter/reverse_http"
        multi_handler.datastore['LPORT']                = "#{port}"

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
        # requester = Metasploit::Aggregator::Http::SslRequester.new(multi_handler.datastore['LHOST'], multi_handler.datastore['LPORT'])
        requester = Metasploit::Aggregator::Http::Requester.new(multi_handler.datastore['LHOST'], multi_handler.datastore['LPORT'])
        requester
      end

      # borrowed from Msf::Sessions::Meterpreter for now
      def guess_target_platform(os)
        case os
          when /windows/i
            Msf::Module::Platform::Windows.realname.downcase
          when /darwin/i
            Msf::Module::Platform::OSX.realname.downcase
          when /mac os ?x/i
            # this happens with java on OSX (for real!)
            Msf::Module::Platform::OSX.realname.downcase
          when /freebsd/i
            Msf::Module::Platform::FreeBSD.realname.downcase
          when /openbsd/i, /netbsd/i
            Msf::Module::Platform::BSD.realname.downcase
          else
            Msf::Module::Platform::Linux.realname.downcase
        end
      end

      def pad_space(status, length)
        while status.length < length
          status << " "
        end
        status
      end

      private :guess_target_platform
      private :aggregator_login
      private :aggregator_compatibility_check
      private :aggregator_verify
      private :local_handler
      private :pad_space
      private :show_session
      private :show_session_detailed
    end

    #
    # Plugin initialization
    #

    def initialize(framework, opts)
      super

      #
      # Require the metasploit/aggregator gem, but fail nicely if it's not there.
      #
      begin
        require "metasploit/aggregator"
      rescue LoadError
        raise "WARNING: metasploit/aggregator is not avaiable for now."
      end

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
