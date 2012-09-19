require 'open3'

module Thin
  # Run a command through the +thin+ command-line script.
  class Command
    include Logging
    
    class << self
      # Path to the +thin+ script used to control the servers.
      # Leave this to default to use the one in the path.
      attr_accessor :script
    end
    
    def initialize(name, options={})
      @name    = name
      @options = options
    end
    
    def self.run(*args)
      new(*args).run
    end
    
    # Send the command to the +thin+ script
    def run
      shell_cmd = shellify
      trace shell_cmd
      trap('INT') {} # Ignore INT signal to pass CTRL+C to subprocess
      Open3.popen3(shell_cmd) do |stdin, stdout, stderr|
        log stdout.gets until stdout.eof?
        log stderr.gets until stderr.eof?
      end
    end
    
    # Turn into a runnable shell command
    def shellify
      shellified_options = @options.inject([]) do |args, (name, value)|
        option_name = name.to_s.tr("_", "-")
        case value
        when NilClass,
             TrueClass then args << "--#{option_name}"
        when FalseClass
        when Array     then value.each { |v| args << "--#{option_name}=#{v.inspect}" }
        else                args << "--#{option_name}=#{value.inspect}"
        end
        args
      end
      
      raise ArgumentError, "Path to thin script can't be found, set Command.script" unless self.class.script
      
      "#{self.class.script} #{@name} #{shellified_options.compact.join(' ')}"
    end
  end
end
