require 'daemons/exceptions'

module Daemons
  require 'daemons/daemonize'

  class Monitor
    def self.find(dir, app_name)
      pid = PidFile.find_files(dir, app_name, false)[0]

      if pid
        pid = PidFile.existing(pid)

        unless PidFile.running?(pid.pid)
          begin; pid.cleanup; rescue ::Exception; end
          return
        end

        monitor = allocate

        monitor.instance_variable_set(:@pid, pid)

        return monitor
      end

      nil
    end

    def initialize(an_app, options = {})
      @app = an_app
      @app_name = an_app.group.app_name + '_monitor'
      @monitor_interval = options[:monitor_interval] || 30

      if an_app.pidfile_dir
        @pid = PidFile.new(an_app.pidfile_dir, @app_name, false)
      else
        @pid = PidMem.new
      end
    end

    def watch(application_group)
      sleep(5)

      loop do
        application_group.applications.each do |a|
          unless a.running?
            a.zap!

            sleep(1)

            Process.detach(fork { a.start(true) })

            sleep(5)
          end
        end

        sleep(@monitor_interval)
      end
    end
    private :watch

    def start_with_pidfile(application_group)
      fork do
        Daemonize.daemonize(nil, @app_name)

        begin
          @pid.pid = Process.pid
          watch(application_group)
        rescue ::Exception => e
          begin
            File.open(@app.logfile, 'a') do |f|
              f.puts Time.now
              f.puts e
              f.puts e.backtrace.inspect
            end
          ensure
            begin; @pid.cleanup; rescue ::Exception; end
            exit!
          end
        end
      end
    end
    private :start_with_pidfile

    def start_without_pidfile(application_group)
      Thread.new { watch(application_group) }
    end
    private :start_without_pidfile

    def start(application_group)
      return if application_group.applications.empty?

      if @pid.kind_of?(PidFile)
        start_with_pidfile(application_group)
      else
        start_without_pidfile(application_group)
      end
    end

    def stop
      begin
        pid = @pid.pid
        Process.kill(Application::SIGNAL, pid)
		      Timeout.timeout(5, TimeoutError) do
            while Pid.running?(pid)
              sleep(0.1)
            end
          end
      rescue ::Exception => e
        $stderr.puts "exception while trying to stop monitor process #{pid}: #{e}"
        $stderr.puts "deleting pid-file."
      end

      # We try to remove the pid-files by ourselves, in case the monitor
      # didn't clean it up.
      begin; @pid.zap; rescue ::Exception; end
    end
  end
end
