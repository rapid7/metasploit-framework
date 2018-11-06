module Daemons
  class Reporter
    attr_reader :options

    def initialize(options)
      @options = options

      if !options[:shush]
        $stdout.sync = true
      end
    end

    def output_message(message)
      if !options[:shush]
        puts message
      end
    end

    def changing_process_privilege(user, group = user)
      output_message "Changing process privilege to #{user}:#{group}"
    end

    def deleted_found_pidfile(pid, f)
      output_message "pid-file for killed process #{pid} found (#{f}), deleting."
    end

    def process_started(app_name, pid)
      output_message  "#{app_name}: process with pid #{pid} started."
    end

    def backtrace_not_supported 
      output_message 'option :backtrace is not supported with :mode => :exec, ignoring'
    end

    def stopping_process(app_name, pid)
      output_message "#{app_name}: trying to stop process with pid #{pid}..."
    end

    def forcefully_stopping_process(app_name, pid)
      output_message "#{app_name}: process with pid #{pid} won't stop, we forcefully kill it..." 
    end

    def cannot_stop_process(app_name, pid)
      output_message "#{app_name}: unable to forcefully kill process with pid #{pid}."
    end

    def stopped_process(app_name, pid)
      output_message "#{app_name}: process with pid #{pid} successfully stopped."
    end

    def status(app_name, running, pid_exists, pid)
      output_message "#{app_name}: #{running ? '' : 'not '}running#{(running and pid_exists) ? ' [pid ' + pid.to_s + ']' : ''}#{(pid_exists and not running) ? ' (but pid-file exists: ' + pid.to_s + ')' : ''}"
    end
  end
end
