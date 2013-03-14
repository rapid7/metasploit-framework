require 'optparse'
require 'stringio'

module Spork
  # This is used by bin/spork. It's wrapped in a class because it's easier to test that way.
  class Runner
    attr_reader :test_framework
    
    def self.run(args, output, error)
      self.new(args, output, error).run
    end
    
    def initialize(args, output, error)
      raise ArgumentError, "expected array of args" unless args.is_a?(Array)
      @output = output
      @error = error
      @options = {}
      opt = OptionParser.new
      opt.banner = "Usage: spork [test framework name] [options]\n\n"
      
      opt.separator "Options:"
      opt.on("-b", "--bootstrap")  {|ignore| @options[:bootstrap] = true }
      opt.on("-d", "--diagnose")  {|ignore| @options[:diagnose] = true }
      opt.on("-h", "--help")  {|ignore| @options[:help] = true }
      opt.on("-p", "--port [PORT]") {|port| @options[:port] = port }
      non_option_args = args.select { |arg| ! args[0].match(/^-/) }
      @options[:server_matcher] = non_option_args[0]
      opt.parse!(args)
      
      if @options[:help]
        @output.puts opt
        @output.puts
        @output.puts supported_test_frameworks_text
        exit(0)
      end
    end
    
    def supported_test_frameworks_text
      text = StringIO.new
      
      text.puts "Supported test frameworks:"
      text.puts Spork::TestFramework.supported_test_frameworks.sort { |a,b| a.short_name <=> b.short_name }.map { |s| (s.available? ? '(*) ' : '( ) ') + s.short_name }
      text.puts "\nLegend: ( ) - not detected in project   (*) - detected\n"
      text.string
    end
    
    # Returns a server for the specified (or the detected default) testing framework.  Returns nil if none detected, or if the specified is not supported or available.
    def find_test_framework
      Spork::TestFramework.factory(@output, @error, options[:server_matcher])
    rescue Spork::TestFramework::NoFrameworksAvailable => e
      @error.puts e.message
    rescue Spork::TestFramework::FactoryException => e
      @error.puts "#{e.message}\n\n#{supported_test_frameworks_text}"
    end
    
    def run
      return false unless test_framework = find_test_framework
      ENV["DRB"] = 'true'
      @error.puts "Using #{test_framework.short_name}"
      @error.flush

      case
      when options[:bootstrap]
        test_framework.bootstrap
      when options[:diagnose]
        require 'spork/diagnoser'
        
        Spork::Diagnoser.install_hook!(test_framework.entry_point)
        test_framework.preload
        Spork::Diagnoser.output_results(@output)
        return true
      else
        run_strategy = Spork::RunStrategy.factory(test_framework)
        return(false) unless run_strategy.preload
        Spork::Server.run(:port => @options[:port] || test_framework.default_port, :run_strategy => run_strategy)
        return true
      end
    end
    
    private
    attr_reader :options 

  end
end






