class Pry

  # Manage the processing of command line options
  class CLI

    NoOptionsError = Class.new(StandardError)

    class << self

      # @return [Proc] The Proc defining the valid command line options.
      attr_accessor :options

      # @return [Array] The Procs that process the parsed options. Plugins can
      #   utilize this facility in order to add and process their own Pry
      #   options.
      attr_accessor :option_processors

      # @return [Array<String>] The input array of strings to process
      #   as CLI options.
      attr_accessor :input_args

      # Add another set of CLI options (a Pry::Slop block)
      def add_options(&block)
        if options
          old_options = options
          self.options = proc do
            instance_exec(&old_options)
            instance_exec(&block)
          end
        else
          self.options = block
        end

        self
      end

      # Bring in options defined in plugins
      def add_plugin_options
        Pry.plugins.values.each do |plugin|
          plugin.load_cli_options
        end

        self
      end

      # Add a block responsible for processing parsed options.
      def add_option_processor(&block)
        self.option_processors ||= []
        option_processors << block

        self
      end

      # Clear `options` and `option_processors`
      def reset
        self.options           = nil
        self.option_processors = nil
      end

      def parse_options(args=ARGV)
        unless options
          raise NoOptionsError, "No command line options defined! Use Pry::CLI.add_options to add command line options."
        end

        # Load config files etc first, ensuring that cli options will take precedence.
        Pry.initial_session_setup

        self.input_args = args

        begin
          opts = Pry::Slop.parse!(
            args,
            :help => true,
            :multiple_switches => false,
            :strict => true,
            &options
          )
        rescue Pry::Slop::InvalidOptionError
          # Display help message on unknown switches and exit.
          puts Pry::Slop.new(&options)
          exit
        end

        Pry.final_session_setup

        # Option processors are optional.
        if option_processors
          option_processors.each { |processor| processor.call(opts) }
        end

        opts
      end

      def start(opts)
        exit if opts.help?

        # invoked via cli
        Pry.cli = true

        # create the actual context
        if opts[:context]
          Pry.initial_session_setup
          context = Pry.binding_for(eval(opts[:context]))
          Pry.final_session_setup
        else
          context = Pry.toplevel_binding
        end

        if Pry::CLI.input_args.any? && Pry::CLI.input_args != ["pry"]
          full_name = File.expand_path(Pry::CLI.input_args.first)
          Pry.load_file_through_repl(full_name)
          exit
        end

        # Start the session (running any code passed with -e, if there is any)
        Pry.start(context, :input => StringIO.new(Pry.config.exec_string))
      end

    end

    reset
  end
end


# Bring in options defined by plugins
Pry::Slop.new do
  on "no-plugins" do
    Pry.config.should_load_plugins = false
  end
end.parse(ARGV.dup)

if Pry.config.should_load_plugins
  Pry::CLI.add_plugin_options
end

# The default Pry command line options (before plugin options are included)
Pry::CLI.add_options do
  banner %{Usage: pry [OPTIONS]
Start a Pry session.
See http://pryrepl.org/ for more information.
Copyright (c) 2016 John Mair (banisterfiend)
--
}
  on :e, :exec=, "A line of code to execute in context before the session starts" do |input|
    Pry.config.exec_string += "\n" if Pry.config.exec_string.length > 0
    Pry.config.exec_string += input
  end

  on "no-pager", "Disable pager for long output" do
    Pry.config.pager = false
  end

  on "no-history", "Disable history loading" do
    Pry.config.history.should_load = false
  end

  on "no-color", "Disable syntax highlighting for session" do
    Pry.config.color = false
  end

  on :f, "Suppress loading of ~/.pryrc and ./.pryrc" do
    Pry.config.should_load_rc = false
    Pry.config.should_load_local_rc = false
  end

  on :s, "select-plugin=", "Only load specified plugin (and no others)." do |plugin_name|
    Pry.config.should_load_plugins = false
    Pry.plugins[plugin_name].activate!
  end

  on :d, "disable-plugin=", "Disable a specific plugin." do |plugin_name|
    Pry.plugins[plugin_name].disable!
  end

  on "no-plugins", "Suppress loading of plugins." do
    Pry.config.should_load_plugins = false
  end

  on "plugins", "List installed plugins." do
    puts "Installed Plugins:"
    puts "--"
    Pry.locate_plugins.each do |plugin|
      puts "#{plugin.name}".ljust(18) << plugin.spec.summary
    end
    exit
  end

  on "simple-prompt", "Enable simple prompt mode" do
    Pry.config.prompt = Pry::SIMPLE_PROMPT
  end

  on "noprompt", "No prompt mode" do
    Pry.config.prompt = Pry::NO_PROMPT
  end

  on :r, :require=, "`require` a Ruby script at startup" do |file|
    Pry.config.requires << file
  end

  on :I=, "Add a path to the $LOAD_PATH", :as => Array, :delimiter => ":" do |load_path|
    load_path.map! do |path|
      /\A\.\// =~ path ? path : File.expand_path(path)
    end

    $LOAD_PATH.unshift(*load_path)
  end

  on "gem", "Shorthand for -I./lib -rgemname" do |load_path|
    $LOAD_PATH.unshift("./lib")
    Dir["./lib/*.rb"].each do |file|
      Pry.config.requires << file
    end
  end

  on :v, :version, "Display the Pry version" do
    puts "Pry version #{Pry::VERSION} on Ruby #{RUBY_VERSION}"
    exit
  end

  on(:c, :context=,
     "Start the session in the specified context. Equivalent to `context.pry` in a session.",
     :default => "Pry.toplevel_binding"
     )
end
