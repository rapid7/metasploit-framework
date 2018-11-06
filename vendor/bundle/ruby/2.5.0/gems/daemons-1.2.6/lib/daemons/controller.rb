
module Daemons
  class Controller
    attr_reader :app_name

    attr_reader :group

    attr_reader :options

    COMMANDS = %w(start stop restart run zap reload status)

    def initialize(options = {}, argv = [])
      @options = options
      @argv = argv

      # Allow an app_name to be specified. If not specified use the
      # basename of the script.
      @app_name = options[:app_name]

      if options[:script]
        @script = File.expand_path(options[:script])

        @app_name ||= File.split(@script)[1]
      end

      @app_name ||= 'unknown_application'

      @command, @controller_part, @app_part = Controller.split_argv(argv)

      # @options[:dir_mode] ||= :script

      @optparse = Optparse.new(self)
    end

    # This function is used to do a final update of the options passed to the application
    # before they are really used.
    #
    # Note that this function should only update <tt>@options</tt> and no other variables.
    #
    def setup_options
    end

    def run
      @options.update @optparse.parse(@controller_part).delete_if { |k, v| !v }

      setup_options

      @group = ApplicationGroup.new(@app_name, @options)
      @group.controller_argv = @controller_part
      @group.app_argv = @app_part

      @group.setup

      case @command
        when 'start'
          @group.new_application.start
        when 'run'
          @options[:ontop] ||= true
          @group.new_application.start
        when 'stop'
          @group.stop_all(@options[:no_wait])
        when 'restart'
          unless @group.applications.empty?
            @group.stop_all(@options[:no_wait])
            sleep(1)
            @group.start_all
          else
            $stderr.puts "#{@group.app_name}: warning: no instances running. Starting..."
            @group.new_application.start
          end
        when 'reload'
          @group.reload_all
        when 'zap'
          @group.zap_all
        when 'status'
          unless @group.applications.empty?
            @group.show_status
            exit 3 if not @group.running?   # exit with status 3 to indicate that no apps are running
          else
            $stderr.puts "#{@group.app_name}: no instances running"
            exit 3                          # exit with status 3 to indicate that no apps are running
          end
        when nil
          fail CmdException.new('no command given')
        else
          fail Error.new("command '#{@command}' not implemented")
      end
    end

    # Split an _argv_ array.
    # +argv+ is assumed to be in the following format:
    #   ['command', 'controller option 1', 'controller option 2', ..., '--', 'app option 1', ...]
    #
    # <tt>command</tt> must be one of the commands listed in <tt>COMMANDS</tt>
    #
    # *Returns*: the command as a string, the controller options as an array, the appliation options
    # as an array
    #
    def self.split_argv(argv)
      argv = argv.dup

      command = nil
      controller_part = []
      app_part = []

      if COMMANDS.include? argv[0]
        command = argv.shift
      end

      if i = argv.index('--')
        # Handle the case where no controller options are given, just
        # options after "--" as well (i == 0)
        controller_part = (i == 0 ? [] : argv[0..i - 1])
        app_part = argv[i + 1..-1]
      else
        controller_part = argv[0..-1]
      end

      [command, controller_part, app_part]
    end
  end
end
