
module Daemons
  class ApplicationGroup
  
    attr_reader :app_name
    attr_reader :script
    
    attr_reader :monitor
    
    #attr_reader :controller
    
    attr_reader :options
    
    attr_reader :applications
    
    attr_accessor :controller_argv
    attr_accessor :app_argv
    
    attr_accessor :dir_mode
    attr_accessor :dir
    
    # true if the application is supposed to run in multiple instances
    attr_reader :multiple
    
    
    def initialize(app_name, options = {})
      @app_name = app_name
      @options = options
      
      if options[:script]
        @script = File.expand_path(options[:script])
      end
      
      #@controller = controller
      @monitor = nil
      
      #options = controller.options
      
      @multiple = options[:multiple] || false
      
      @dir_mode = options[:dir_mode] || :script
      @dir = options[:dir] || ''
      
      @keep_pid_files = options[:keep_pid_files] || false
      @no_pidfiles = options[:no_pidfiles] || false
      
      #@applications = find_applications(pidfile_dir())
      @applications = []
    end
    
    # Setup the application group.
    # Currently this functions calls <tt>find_applications</tt> which finds
    # all running instances of the application and populates the application array.
    #
    def setup
      @applications = find_applications(pidfile_dir())
    end
    
    def pidfile_dir
      PidFile.dir(@dir_mode, @dir, script)
    end  
    
    def find_applications(dir)
      if @no_pidfiles
        return find_applications_by_app_name(app_name)
      else
        return find_applications_by_pidfiles(dir)
      end
    end
    
    # TODO: identifiy the monitor process
    def find_applications_by_app_name(app_name)
      pids = []
      
      begin
      x = `ps auxw | grep -v grep | awk '{print $2, $11, $12}' | grep #{app_name}`
      if x && x.chomp!
        processes = x.split(/\n/).compact
        processes = processes.delete_if do |p|
          pid, name, add = p.split(/\s/)
          # We want to make sure that the first part of the process name matches
          # so that app_name matches app_name_22
          
          app_name != name[0..(app_name.length - 1)] and not add.include?(app_name)
        end
        pids = processes.map {|p| p.split(/\s/)[0].to_i}
      end
      rescue ::Exception
      end
      
      return pids.map {|f|
        app = Application.new(self, {}, PidMem.existing(f))
        setup_app(app)
        app
      }
    end
    
    def find_applications_by_pidfiles(dir)
      pid_files = PidFile.find_files(dir, app_name, ! @keep_pid_files)
      
      #pp pid_files
      
      @monitor = Monitor.find(dir, app_name + '_monitor')
      
      pid_files.reject! {|f| f =~ /_monitor.pid$/}
      
      return pid_files.map {|f|
        app = Application.new(self, {}, PidFile.existing(f))
        setup_app(app)
        app
      }
    end
    
    def new_application(add_options = {})
      if @applications.size > 0 and not @multiple
        if options[:force]
          @applications.delete_if {|a|
            unless a.running?
              a.zap
              true
            end
          }
        end
        
        raise RuntimeException.new('there is already one or more instance(s) of the program running') unless @applications.empty?
      end
      
      app = Application.new(self, add_options)
      
      setup_app(app)
      
      @applications << app
      
      return app
    end
    
    def setup_app(app)
      app.controller_argv = @controller_argv
      app.app_argv = @app_argv
    end
    private :setup_app
    
    def create_monitor(an_app)
      return if @monitor
      
      if options[:monitor]
        @monitor = Monitor.new(an_app)

        @monitor.start(@applications)
      end
    end
    
    def start_all
      @monitor.stop if @monitor
      @monitor = nil
      
      @applications.each {|a| 
        fork { 
          a.start 
        } 
      }
    end
    
    def stop_all(no_wait = false)
      @monitor.stop if @monitor
      
      threads = []
      
      @applications.each {|a| 
        threads << Thread.new do
          a.stop(no_wait)
        end
      }
      
      threads.each {|t| t.join}
    end
    
    def reload_all
      @applications.each {|a| a.reload}
    end

    def zap_all
      @monitor.stop if @monitor
      
      @applications.each {|a| a.zap}
    end
    
    def show_status
      @applications.each {|a| a.show_status}
    end
    
  end

end
