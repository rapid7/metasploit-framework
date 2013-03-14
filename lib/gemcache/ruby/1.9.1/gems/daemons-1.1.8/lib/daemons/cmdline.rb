
module Daemons

  class Optparse
  
    attr_reader :usage

    def initialize(controller)
      @controller = controller
      @options = {}
      
      @opts = OptionParser.new do |opts|
        opts.banner = ""
        
#         opts.on("-v", "--[no-]verbose", "Run verbosely") do |v|
#           @options[:verbose] = v
#         end
        
        opts.on("-t", "--ontop", "Stay on top (does not daemonize)") do |t|
          @options[:ontop] = t
        end
        
        opts.on("-f", "--force", "Force operation") do |t|
          @options[:force] = t
        end
        
        opts.on("-n", "--no_wait", "Do not wait for processes to stop") do |t|
          @options[:no_wait] = t
        end
        
        #opts.separator ""
        #opts.separator "Specific options:"

        
        opts.separator ""
        opts.separator "Common options:"

        # No argument, shows at tail.  This will print an options summary
        opts.on_tail("-h", "--help", "Show this message") do
          #puts opts
          #@usage = 
          controller.print_usage()
          
          exit
        end

        # Switch to print the version.
        opts.on_tail("--version", "Show version") do
          puts "daemons version #{Daemons::VERSION}"
          exit
        end
      end  
      
      begin
        @usage = @opts.to_s
      rescue ::Exception # work around a bug in ruby 1.9
        @usage = <<END
            -t, --ontop                      Stay on top (does not daemonize)
            -f, --force                      Force operation
            -n, --no_wait                    Do not wait for processes to stop

        Common options:
            -h, --help                       Show this message
                --version                    Show version
END
      end
    end
    
    
    #
    # Return a hash describing the options.
    #
    def parse(args)
      # The options specified on the command line will be collected in *options*.
      # We set default values here.
      #options = {}
      
      
      ##pp args
      @opts.parse(args)
      
      return @options
    end

  end
  
  
  class Controller
  
    def print_usage
      puts "Usage: #{@app_name} <command> <options> -- <application options>"
      puts
      puts "* where <command> is one of:"
      puts "  start         start an instance of the application"
      puts "  stop          stop all instances of the application"
      puts "  restart       stop all instances and restart them afterwards"
      puts "  reload        send a SIGHUP to all instances of the application"
      puts "  run           start the application and stay on top"
      puts "  zap           set the application to a stopped state"
      puts "  status        show status (PID) of application instances"
      puts
      puts "* and where <options> may contain several of the following:"
      
      puts @optparse.usage
    end
    
    def catch_exceptions(&block)
      begin
        block.call
      rescue CmdException, OptionParser::ParseError => e
        puts "ERROR: #{e.to_s}"
        puts
        print_usage()
      rescue RuntimeException => e
        puts "ERROR: #{e.to_s}"
      end
    end
    
  end
  
end
