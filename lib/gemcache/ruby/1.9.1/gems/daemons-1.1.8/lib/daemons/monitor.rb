
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
        
        monitor = self.allocate
      
        monitor.instance_variable_set(:@pid, pid)
        
        return monitor
      end
      
      return nil
    end
    
    
    def initialize(an_app)
      @app = an_app
      @app_name = an_app.group.app_name + '_monitor'
      
      if an_app.pidfile_dir
        @pid = PidFile.new(an_app.pidfile_dir, @app_name, false)
      else
        @pid = PidMem.new
      end
    end
    
    def watch(applications)
      sleep(30)
      
      loop do
        applications.each {|a|
          sleep(10)
          
          unless a.running?
            a.zap!
            
            Process.detach(fork { a.start })
            
            sleep(10)
          end
        }
        
        sleep(30)
      end
    end
    private :watch
    
    
    def start_with_pidfile(applications)
      fork do
        Daemonize.daemonize(nil, @app_name)
        
        begin  
          @pid.pid = Process.pid
          
  #         at_exit {
  # begin; @pid.cleanup; rescue ::Exception; end
  #         }
          
          # This part is needed to remove the pid-file if the application is killed by 
          # daemons or manually by the user.
          # Note that the applications is not supposed to overwrite the signal handler for
          # 'TERM'.
          #
  #         trap('TERM') {
  # begin; @pid.cleanup; rescue ::Exception; end
  #           exit
  #         }
          
          watch(applications)
        rescue ::Exception => e
          begin
            File.open(@app.logfile, 'a') {|f|
              f.puts Time.now
              f.puts e
              f.puts e.backtrace.inspect
            }
          ensure 
            begin; @pid.cleanup; rescue ::Exception; end
            exit!
          end
        end
      end
    end
    private :start_with_pidfile
    
    def start_without_pidfile(applications)
      Thread.new { watch(applications) }
    end
    private :start_without_pidfile
    
    
    def start(applications)
      return if applications.empty?
      
      if @pid.kind_of?(PidFile)
        start_with_pidfile(applications)
      else
        start_without_pidfile(applications)
      end
    end
    
    
    def stop
      begin
        pid = @pid.pid
        Process.kill(Application::SIGNAL, pid)
		Timeout::timeout(5) {      
          while Pid.running?(pid)
            sleep(0.1)
          end
        }
      rescue ::Exception => e
        puts "#{e} #{pid}"
        puts "deleting pid-file."
      end
      
      # We try to remove the pid-files by ourselves, in case the application
      # didn't clean it up.
      begin; @pid.cleanup; rescue ::Exception; end
    end
    
  end 
end