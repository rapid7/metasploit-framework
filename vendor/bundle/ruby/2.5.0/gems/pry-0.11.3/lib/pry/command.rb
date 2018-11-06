require 'delegate'
require 'pry/helpers/documentation_helpers'

class Pry

  # The super-class of all commands, new commands should be created by calling
  # {Pry::CommandSet#command} which creates a BlockCommand or {Pry::CommandSet#create_command}
  # which creates a ClassCommand. Please don't use this class directly.
  class Command
    extend Helpers::DocumentationHelpers
    extend CodeObject::Helpers

    # represents a void return value for a command
    VOID_VALUE = Object.new

    # give it a nice inspect
    def VOID_VALUE.inspect() "void" end

    # Properties of the command itself (as passed as arguments to
    # {CommandSet#command} or {CommandSet#create_command}).
    class << self
      attr_writer :block
      attr_writer :description
      attr_writer :command_options
      attr_writer :match

      def match(arg=nil)
        if arg
          @command_options ||= default_options(arg)
          @command_options[:listing] = arg.is_a?(String) ? arg : arg.inspect
          @match = arg
        end
        @match ||= nil
      end

      # Define or get the command's description
      def description(arg=nil)
        @description = arg if arg
        @description ||= nil
      end

      # Define or get the command's options
      def command_options(arg=nil)
        @command_options ||= default_options(match)
        @command_options.merge!(arg) if arg
        @command_options
      end
      # backward compatibility
      alias_method :options, :command_options
      alias_method :options=, :command_options=

      # Define or get the command's banner
      def banner(arg=nil)
        @banner = arg if arg
        @banner ||= description
      end

      def block
        @block || instance_method(:process)
      end

      def source
        file, line = block.source_location
        strip_leading_whitespace(Pry::Code.from_file(file).expression_at(line))
      end

      def doc
        new.help
      end

      def source_location
        block.source_location
      end

      def source_file
        Array(block.source_location).first
      end
      alias_method :file, :source_file

      def source_line
        Array(block.source_location).last
      end
      alias_method :line, :source_line

      def default_options(match)
        {
          :requires_gem      => [],
          :keep_retval       => false,
          :argument_required => false,
          :interpolate       => true,
          :shellwords        => true,
          :listing           => (String === match ? match : match.inspect),
          :use_prefix        => true,
          :takes_block       => false
        }
      end
    end

    # Make those properties accessible to instances
    def name; self.class.name; end
    def match; self.class.match; end
    def description; self.class.description; end
    def block; self.class.block; end
    def command_options; self.class.options; end
    def command_name; self.class.command_name; end
    def source; self.class.source; end
    def source_location; self.class.source_location; end

    class << self
      def name
        super.to_s == "" ? "#<class(Pry::Command #{match.inspect})>" : super
      end

      def inspect
        name
      end

      def command_name
        self.options[:listing]
      end

      # Create a new command with the given properties.
      # @param [String, Regex] match The thing that triggers this command
      # @param [String] description The description to appear in `help`
      # @param [Hash] options Behavioral options (see {Pry::CommandSet#command})
      # @param [Module] helpers A module of helper functions to be included.
      # @yield optional, used for BlockCommands
      # @return [Class] (a subclass of {Pry::Command})
      def subclass(match, description, options, helpers, &block)
        klass = Class.new(self)
        klass.send(:include, helpers)
        klass.match = match
        klass.description = description
        klass.command_options = options
        klass.block = block
        klass
      end

      # Should this command be called for the given line?
      # @param [String] val A line input at the REPL
      # @return [Boolean]
      def matches?(val)
        command_regex =~ val
      end

      # How well does this command match the given line?
      #
      # Higher scores are better because they imply that this command matches
      # the line more closely.
      #
      # The score is calculated by taking the number of characters at the start
      # of the string that are used only to identify the command, not as part of
      # the arguments.
      #
      # @example
      #   /\.(.*)/.match_score(".foo") #=> 1
      #   /\.*(.*)/.match_score("...foo") #=> 3
      #   'hi'.match_score("hi there") #=> 2
      #
      # @param [String] val A line input at the REPL
      # @return [Fixnum]
      def match_score(val)
        if command_regex =~ val
          Regexp.last_match.size > 1 ? Regexp.last_match.begin(1) : Regexp.last_match.end(0)
        else
          -1
        end
      end

      # @deprecated Replaced with {Pry::Hooks#add_hook}. Left for compatibility.
      # Store hooks to be run before or after the command body.
      # @see {Pry::CommandSet#before_command}
      # @see {Pry::CommandSet#after_command}
      def hooks
        Pry.hooks
      end

      def command_regex
        pr = Pry.respond_to?(:config) ? Pry.config.command_prefix : ""
        prefix = convert_to_regex(pr)
        prefix = "(?:#{prefix})?" unless options[:use_prefix]

        /^#{prefix}#{convert_to_regex(match)}(?!\S)/
      end

      def convert_to_regex(obj)
        case obj
        when String
          Regexp.escape(obj)
        else
          obj
        end
      end

      # The group in which the command should be displayed in "help" output.
      # This is usually auto-generated from directory naming, but it can be
      # manually overridden if necessary.
      # Group should not be changed once it is initialized.
      def group(name=nil)
        @group ||= if name
                     name
                   else
                     case Pry::Method(block).source_file
                     when %r{/pry/.*_commands/(.*).rb}
                       $1.capitalize.gsub(/_/, " ")
                     when %r{(pry-\w+)-([\d\.]+([\w\.]+)?)}
                       name, version = $1, $2
                       "#{name.to_s} (v#{version.to_s})"
                     when /pryrc/
                       "~/.pryrc"
                     else
                       "(other)"
                     end
                   end
      end
    end

    # Properties of one execution of a command (passed by {Pry#run_command} as a hash of
    # context and expanded in `#initialize`
    attr_accessor :output
    attr_accessor :target
    attr_accessor :captures
    attr_accessor :eval_string
    attr_accessor :arg_string
    attr_accessor :context
    attr_accessor :command_set
    attr_accessor :hooks
    attr_accessor :_pry_

    # The block we pass *into* a command so long as `:takes_block` is
    # not equal to `false`
    # @example
    #   my-command | do
    #     puts "block content"
    #   end
    attr_accessor :command_block

    # Run a command from another command.
    # @param [String] command_string The string that invokes the command
    # @param [Array] args Further arguments to pass to the command
    # @example
    #   run "show-input"
    # @example
    #   run ".ls"
    # @example
    #   run "amend-line",  "5", 'puts "hello world"'
    def run(command_string, *args)
      command_string = _pry_.config.command_prefix.to_s + command_string
      complete_string = "#{command_string} #{args.join(" ")}".rstrip
      command_set.process_line(complete_string, context)
    end

    def commands
      command_set.to_hash
    end

    def text
      Pry::Helpers::Text
    end

    def void
      VOID_VALUE
    end

    include Pry::Helpers::BaseHelpers
    include Pry::Helpers::CommandHelpers

    # Instantiate a command, in preparation for calling it.
    # @param [Hash] context The runtime context to use with this command.
    def initialize(context={})
      self.context      = context
      self.target       = context[:target]
      self.output       = context[:output]
      self.eval_string  = context[:eval_string]
      self.command_set  = context[:command_set]
      self.hooks        = context[:hooks]
      self._pry_        = context[:pry_instance]
    end

    # @return [Object] The value of `self` inside the `target` binding.
    def target_self; target.eval('self'); end

    # @return [Hash] Pry commands can store arbitrary state
    #   here. This state persists between subsequent command invocations.
    #   All state saved here is unique to the command, it does not
    #   need to be namespaced.
    # @example
    #   state.my_state = "my state"  # this will not conflict with any
    #                                # `state.my_state` used in another command.
    def state
      _pry_.command_state[match] ||= Pry::Config.from_hash({})
    end

    # Revaluate the string (str) and perform interpolation.
    # @param [String] str The string to reevaluate with interpolation.
    #
    # @return [String] The reevaluated string with interpolations
    #   applied (if any).
    def interpolate_string(str)
      dumped_str = str.dump
      if dumped_str.gsub!(/\\\#\{/, '#{')
        target.eval(dumped_str)
      else
        str
      end
    end

    # Display a warning if a command collides with a local/method in
    # the current scope.
    def check_for_command_collision(command_match, arg_string)
      collision_type = target.eval("defined?(#{command_match})")
      collision_type ||= 'local-variable' if arg_string.match(%r{\A\s*[-+*/%&|^]*=})

      if collision_type
        output.puts "#{text.bold('WARNING:')} Calling Pry command '#{command_match}', which conflicts with a #{collision_type}.\n\n"
      end
    rescue Pry::RescuableException
    end

    # Extract necessary information from a line that Command.matches? this
    # command.
    #
    # Returns an array of four elements:
    #
    # ```
    #  [String] the portion of the line that matched with the Command match
    #  [String] a string of all the arguments (i.e. everything but the match)
    #  [Array]  the captures caught by the command_regex
    #  [Array]  the arguments obtained by splitting the arg_string
    # ```
    #
    # @param [String] val The line of input
    # @return [Array]
    def tokenize(val)
      val.replace(interpolate_string(val)) if command_options[:interpolate]

      self.class.command_regex =~ val

      # please call Command.matches? before Command#call_safely
      raise CommandError, "fatal: called a command which didn't match?!" unless Regexp.last_match
      captures = Regexp.last_match.captures
      pos = Regexp.last_match.end(0)

      arg_string = val[pos..-1]

      # remove the one leading space if it exists
      arg_string.slice!(0) if arg_string.start_with?(" ")

      # process and pass a block if one is found
      pass_block(arg_string) if command_options[:takes_block]

      if arg_string
        args = command_options[:shellwords] ? Shellwords.shellwords(arg_string) : arg_string.split(" ")
      else
        args = []
      end

      [val[0..pos].rstrip, arg_string, captures, args]
    end

    # Process a line that Command.matches? this command.
    # @param [String] line The line to process
    # @return [Object, Command::VOID_VALUE]
    def process_line(line)
      command_match, arg_string, captures, args = tokenize(line)

      check_for_command_collision(command_match, arg_string) if Pry.config.collision_warning

      self.arg_string = arg_string
      self.captures = captures

      call_safely(*(captures + args))
    end

    # Pass a block argument to a command.
    # @param [String] arg_string The arguments (as a string) passed to the command.
    #   We inspect these for a '| do' or a '| {' and if we find it we use it
    #   to start a block input sequence. Once we have a complete
    #   block, we save it to an accessor that can be retrieved from the command context.
    #   Note that if we find the '| do' or '| {' we delete this and the
    #   elements following it from `arg_string`.
    def pass_block(arg_string)
      # Workaround for weird JRuby bug where rindex in this case can return nil
      # even when there's a match.
      arg_string.scan(/\| *(?:do|\{)/)
      block_index = $~ && $~.offset(0)[0]

      return if !block_index

      block_init_string = arg_string.slice!(block_index..-1)[1..-1]
      prime_string = "proc #{block_init_string}\n"

      if !Pry::Code.complete_expression?(prime_string)
        block_string = _pry_.r(target, prime_string)
      else
        block_string = prime_string
      end

      begin
        self.command_block = target.eval(block_string)
      rescue Pry::RescuableException
        raise CommandError, "Incomplete block definition."
      end
    end

    private :pass_block

    # Run the command with the given `args`.
    #
    # This is a public wrapper around `#call` which ensures all preconditions
    # are met.
    #
    # @param [Array<String>] args The arguments to pass to this command.
    # @return [Object] The return value of the `#call` method, or
    #   {Command::VOID_VALUE}.
    def call_safely(*args)
      unless dependencies_met?
        gems_needed = Array(command_options[:requires_gem])
        gems_not_installed = gems_needed.select { |g| !Rubygem.installed?(g) }
        output.puts "\nThe command '#{command_name}' is #{text.bold("unavailable")} because it requires the following gems to be installed: #{(gems_not_installed.join(", "))}"
        output.puts "-"
        output.puts "Type `install-command #{command_name}` to install the required gems and activate this command."
        return void
      end

      if command_options[:argument_required] && args.empty?
        raise CommandError, "The command '#{command_name}' requires an argument."
      end

      ret = use_unpatched_symbol do
        call_with_hooks(*args)
      end
      command_options[:keep_retval] ? ret : void
    end

    def use_unpatched_symbol
      call_method = Symbol.method_defined?(:call) && Symbol.instance_method(:call)
      Symbol.class_eval { undef :call } if call_method
      yield
    ensure
      Symbol.instance_eval { define_method(:call, call_method) } if call_method
    end

    # Are all the gems required to use this command installed?
    #
    # @return  Boolean
    def dependencies_met?
      @dependencies_met ||= command_dependencies_met?(command_options)
    end

    # Generate completions for this command
    #
    # @param [String] search  The line typed so far
    # @return [Array<String>]  Completion words
    def complete(search)
      []
    end

    private

    def find_hooks(event)
      event_name = "#{event}_#{command_name}"
      (self.hooks || self.class.hooks).get_hooks(event_name).values
    end

    def before_hooks
      find_hooks('before')
    end

    def after_hooks
      find_hooks('after')
    end

    # Run the `#call` method and all the registered hooks.
    # @param [Array<String>] args The arguments to `#call`
    # @return [Object] The return value from `#call`
    def call_with_hooks(*args)
      before_hooks.each { |block| instance_exec(*args, &block) }

      ret = call(*args)

      after_hooks.each do |block|
        ret = instance_exec(*args, &block)
      end

      ret
    end

    # Fix the number of arguments we pass to a block to avoid arity warnings.
    # @param [Fixnum] arity The arity of the block
    # @param [Array] args The arguments to pass
    # @return [Array] A (possibly shorter) array of the arguments to pass
    def correct_arg_arity(arity, args)
      case
      when arity < 0
        args
      when arity == 0
        []
      when arity > 0
        args.values_at(*(0..(arity - 1)).to_a)
      end
    end
  end

  # A super-class for Commands that are created with a single block.
  #
  # This class ensures that the block is called with the correct number of arguments
  # and the right context.
  #
  # Create subclasses using {Pry::CommandSet#command}.
  class BlockCommand < Command
    # backwards compatibility
    alias_method :opts, :context

    # Call the block that was registered with this command.
    # @param [Array<String>] args The arguments passed
    # @return [Object] The return value of the block
    def call(*args)
      instance_exec(*correct_arg_arity(block.arity, args), &block)
    end

    def help
      "#{command_options[:listing].to_s.ljust(18)} #{description}"
    end
  end

  # A super-class of Commands with structure.
  #
  # This class implements the bare-minimum functionality that a command should
  # have, namely a --help switch, and then delegates actual processing to its
  # subclasses.
  #
  # Create subclasses using {Pry::CommandSet#create_command}, and override the
  # `options(opt)` method to set up an instance of Pry::Slop, and the `process`
  # method to actually run the command. If necessary, you can also override
  # `setup` which will be called before `options`, for example to require any
  # gems your command needs to run, or to set up state.
  class ClassCommand < Command
    class << self

      # Ensure that subclasses inherit the options, description and
      # match from a ClassCommand super class.
      def inherited(klass)
        klass.match  match
        klass.description  description
        klass.command_options options
      end

      def source
        source_object.source
      end

      def doc
        new.help
      end

      def source_location
        source_object.source_location
      end

      def source_file
        source_object.source_file
      end
      alias_method :file, :source_file

      def source_line
        source_object.source_line
      end
      alias_method :line, :source_line

      private

      # The object used to extract the source for the command.
      #
      # This should be a `Pry::Method(block)` for a command made with `create_command`
      # and a `Pry::WrappedModule(self)` for a command that's a standard class.
      # @return [Pry::WrappedModule, Pry::Method]
      def source_object
        @source_object ||= if name =~ /^[A-Z]/
                             Pry::WrappedModule(self)
                           else
                             Pry::Method(block)
                           end
      end
    end

    attr_accessor :opts
    attr_accessor :args

    # Set up `opts` and `args`, and then call `process`.
    #
    # This method will display help if necessary.
    #
    # @param [Array<String>] args The arguments passed
    # @return [Object] The return value of `process` or VOID_VALUE
    def call(*args)
      setup

      self.opts = slop
      self.args = self.opts.parse!(args)

      if opts.present?(:help)
        output.puts slop.help
        void
      else
        process(*correct_arg_arity(method(:process).arity, args))
      end
    end

    # Return the help generated by Pry::Slop for this command.
    def help
      slop.help
    end

    # Return an instance of Pry::Slop that can parse either subcommands or the
    # options that this command accepts.
    def slop
      Pry::Slop.new do |opt|
        opt.banner(unindent(self.class.banner))
        subcommands(opt)
        options(opt)
        opt.on :h, :help, 'Show this message.'
      end
    end

    # Generate shell completions
    # @param [String] search  The line typed so far
    # @return [Array<String>]  the words to complete
    def complete(search)
      slop.flat_map do |opt|
        [opt.long && "--#{opt.long} " || opt.short && "-#{opt.short}"]
      end.compact + super
    end

    # A method called just before `options(opt)` as part of `call`.
    #
    # This method can be used to set up any context your command needs to run,
    # for example requiring gems, or setting default values for options.
    #
    # @example
    #   def setup
    #     require 'gist'
    #     @action = :method
    #   end
    def setup; end

    # A method to setup Pry::Slop commands so it can parse the subcommands your
    # command expects. If you need to set up default values, use `setup`
    # instead.
    #
    # @example A minimal example
    #   def subcommands(cmd)
    #     cmd.command :download do |opt|
    #       description 'Downloads a content from a server'
    #
    #       opt.on :verbose, 'Use verbose output'
    #
    #       run do |options, arguments|
    #         ContentDownloader.download(options, arguments)
    #       end
    #     end
    #   end
    #
    # @example Define the invokation block anywhere you want
    #   def subcommands(cmd)
    #     cmd.command :download do |opt|
    #       description 'Downloads a content from a server'
    #
    #       opt.on :verbose, 'Use verbose output'
    #     end
    #   end
    #
    #   def process
    #     # Perform calculations...
    #     opts.fetch_command(:download).run do |options, arguments|
    #       ContentDownloader.download(options, arguments)
    #     end
    #     # More calculations...
    #   end
    def subcommands(cmd); end

    # A method to setup Pry::Slop so it can parse the options your command expects.
    #
    # @note Please don't do anything side-effecty in the main part of this
    # method, as it may be called by Pry at any time for introspection reasons.
    # If you need to set up default values, use `setup` instead.
    #
    # @example
    #  def options(opt)
    #    opt.banner "Gists methods or classes"
    #    opt.on(:c, :class, "gist a class") do
    #      @action = :class
    #    end
    #  end
    def options(opt); end

    # The actual body of your command should go here.
    #
    # The `opts` mehod can be called to get the options that Pry::Slop has passed,
    # and `args` gives the remaining, unparsed arguments.
    #
    # The return value of this method is discarded unless the command was
    # created with `:keep_retval => true`, in which case it is returned to the
    # repl.
    #
    # @example
    #   def process
    #     if opts.present?(:class)
    #       gist_class
    #     else
    #       gist_method
    #     end
    #   end
    def process; raise CommandError, "command '#{command_name}' not implemented" end
  end
end
