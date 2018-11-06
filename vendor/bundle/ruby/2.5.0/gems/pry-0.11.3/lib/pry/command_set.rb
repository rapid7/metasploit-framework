class Pry
  class NoCommandError < StandardError
    def initialize(match, owner)
      super "Command '#{match}' not found in command set #{owner}"
    end
  end

  # This class is used to create sets of commands. Commands can be imported from
  # different sets, aliased, removed, etc.
  class CommandSet
    include Enumerable
    include Pry::Helpers::BaseHelpers
    attr_reader :helper_module

    # @param [Array<Commandset>] imported_sets
    #   Sets which will be imported automatically
    # @yield Optional block run to define commands
    def initialize(*imported_sets, &block)
      @commands      = {}
      @helper_module = Module.new
      import(*imported_sets)
      instance_eval(&block) if block
    end

    # Defines a new Pry command.
    # @param [String, Regexp] match The start of invocations of this command.
    # @param [String] description A description of the command.
    # @param [Hash] options The optional configuration parameters.
    # @option options [Boolean] :keep_retval Whether or not to use return value
    #   of the block for return of `command` or just to return `nil`
    #   (the default).
    # @option options [Array<String>] :requires_gem Whether the command has
    #   any gem dependencies, if it does and dependencies not met then
    #   command is disabled and a stub proc giving instructions to
    #   install command is provided.
    # @option options [Boolean] :interpolate Whether string #{} based
    #   interpolation is applied to the command arguments before
    #   executing the command. Defaults to true.
    # @option options [String] :listing The listing name of the
    #   command. That is the name by which the command is looked up by
    #   help and by show-command. Necessary for commands with regex matches.
    # @option options [Boolean] :use_prefix Whether the command uses
    #   `Pry.config.command_prefix` prefix (if one is defined). Defaults
    #   to true.
    # @option options [Boolean] :shellwords Whether the command's arguments
    #   should be split using Shellwords instead of just split on spaces.
    #   Defaults to true.
    # @yield The action to perform. The parameters in the block
    #   determines the parameters the command will receive. All
    #   parameters passed into the block will be strings. Successive
    #   command parameters are separated by whitespace at the Pry prompt.
    # @example
    #   MyCommands = Pry::CommandSet.new do
    #     command "greet", "Greet somebody" do |name|
    #       puts "Good afternoon #{name.capitalize}!"
    #     end
    #   end
    #
    #   # From pry:
    #   # pry(main)> _pry_.commands = MyCommands
    #   # pry(main)> greet john
    #   # Good afternoon John!
    #   # pry(main)> help greet
    #   # Greet somebody
    # @example Regexp command
    #   MyCommands = Pry::CommandSet.new do
    #     command /number-(\d+)/, "number-N regex command", :listing => "number" do |num, name|
    #       puts "hello #{name}, nice number: #{num}"
    #     end
    #   end
    #
    #   # From pry:
    #   # pry(main)> _pry_.commands = MyCommands
    #   # pry(main)> number-10 john
    #   # hello john, nice number: 10
    #   # pry(main)> help number
    #   # number-N regex command
    def block_command(match, description="No description.", options={}, &block)
      description, options = ["No description.", description] if description.is_a?(Hash)
      options = Pry::Command.default_options(match).merge!(options)

      @commands[match] = Pry::BlockCommand.subclass(match, description, options, helper_module, &block)
    end
    alias_method :command, :block_command

    # Defines a new Pry command class.
    #
    # @param [String, Regexp] match The start of invocations of this command.
    # @param [String] description A description of the command.
    # @param [Hash] options The optional configuration parameters, see {#command}
    # @yield The class body's definition.
    #
    # @example
    #   Pry::Commands.create_command "echo", "echo's the input", :shellwords => false do
    #     def options(opt)
    #       opt.banner "Usage: echo [-u | -d] <string to echo>"
    #       opt.on :u, :upcase, "ensure the output is all upper-case"
    #       opt.on :d, :downcase, "ensure the output is all lower-case"
    #     end
    #
    #     def process
    #       raise Pry::CommandError, "-u and -d makes no sense" if opts.present?(:u) && opts.present?(:d)
    #       result = args.join(" ")
    #       result.downcase! if opts.present?(:downcase)
    #       result.upcase! if opts.present?(:upcase)
    #       output.puts result
    #     end
    #   end
    #
    def create_command(match, description="No description.", options={}, &block)
      description, options = ["No description.", description] if description.is_a?(Hash)
      options = Pry::Command.default_options(match).merge!(options)

      @commands[match] = Pry::ClassCommand.subclass(match, description, options, helper_module, &block)
      @commands[match].class_eval(&block)
      @commands[match]
    end

    # Execute a block of code before a command is invoked. The block also
    # gets access to parameters that will be passed to the command and
    # is evaluated in the same context.
    # @param [String, Regexp] search The match or listing of the command.
    # @yield The block to be run before the command.
    # @example Display parameter before invoking command
    #   Pry.config.commands.before_command("whereami") do |n|
    #     output.puts "parameter passed was #{n}"
    #   end
    # @deprecated Use {Pry::Hooks#add_hook} instead.
    def before_command(search, &block)
      cmd = find_command_by_match_or_listing(search)
      cmd.hooks.add_hook("before_#{cmd.command_name}", random_hook_name, block)
    end

    # Execute a block of code after a command is invoked. The block also
    # gets access to parameters that will be passed to the command and
    # is evaluated in the same context.
    # @param [String, Regexp] search The match or listing of the command.
    # @yield The block to be run after the command.
    # @example Display text 'command complete' after invoking command
    #   Pry.config.commands.after_command("whereami") do |n|
    #     output.puts "command complete!"
    #   end
    # @deprecated Use {Pry::Hooks#add_hook} instead.
    def after_command(search, &block)
      cmd = find_command_by_match_or_listing(search)
      cmd.hooks.add_hook("after_#{cmd.command_name}", random_hook_name, block)
    end

    def random_hook_name
      (0...8).map { ('a'..'z').to_a[rand(26)] }.join
    end
    private :random_hook_name

    def each(&block)
      @commands.each(&block)
    end

    # Removes some commands from the set
    # @param [Array<String>] searches the matches or listings of the commands to remove
    def delete(*searches)
      searches.each do |search|
        cmd = find_command_by_match_or_listing(search)
        @commands.delete cmd.match
      end
    end

    # Imports all the commands from one or more sets.
    # @param [Array<CommandSet>] sets Command sets, all of the commands of which
    #   will be imported.
    # @return [Pry::CommandSet] Returns the reciever (a command set).
    def import(*sets)
      sets.each do |set|
        @commands.merge! set.to_hash
        helper_module.send :include, set.helper_module
      end
      self
    end

    # Imports some commands from a set
    # @param [CommandSet] set Set to import commands from
    # @param [Array<String>] matches Commands to import
    # @return [Pry::CommandSet] Returns the reciever (a command set).
    def import_from(set, *matches)
      helper_module.send :include, set.helper_module
      matches.each do |match|
        cmd = set.find_command_by_match_or_listing(match)
        @commands[cmd.match] = cmd
      end
      self
    end

    # @param [String, Regexp] match_or_listing The match or listing of a command.
    #   of the command to retrieve.
    # @return [Command] The command object matched.
    def find_command_by_match_or_listing(match_or_listing)
      cmd = (@commands[match_or_listing] ||
        Pry::Helpers::BaseHelpers.find_command(match_or_listing, @commands))
      cmd or raise ArgumentError, "Cannot find a command: '#{match_or_listing}'!"
    end

    # Aliases a command
    # @param [String, Regex] match The match of the alias (can be a regex).
    # @param [String] action The action to be performed (typically
    #   another command).
    # @param [Hash] options The optional configuration parameters,
    #   accepts the same as the `command` method, but also allows the
    #   command description to be passed this way too as `:desc`
    # @example Creating an alias for `ls -M`
    #   Pry.config.commands.alias_command "lM", "ls -M"
    # @example Pass explicit description (overriding default).
    #   Pry.config.commands.alias_command "lM", "ls -M", :desc => "cutiepie"
    def alias_command(match, action,  options={})
      cmd = find_command(action) or fail "Command: `#{action}` not found"
      original_options = cmd.options.dup

      options = original_options.merge!({
                                          :desc => "Alias for `#{action}`",
                                          :listing => match
                                        }).merge!(options)

      # ensure default description is used if desc is nil
      desc = options.delete(:desc).to_s

      c = block_command match, desc, options do |*args|
        run action, *args
      end

      c.class_eval do
        define_method(:complete) do |input|
          cmd.new(context).complete(input)
        end
      end

      c.group "Aliases"

      c
    end

    # Rename a command. Accepts either match or listing for the search.
    #
    # @param [String, Regexp] new_match The new match for the command.
    # @param [String, Regexp] search The command's current match or listing.
    # @param [Hash] options The optional configuration parameters,
    #   accepts the same as the `command` method, but also allows the
    #   command description to be passed this way too.
    # @example Renaming the `ls` command and changing its description.
    #   Pry.config.commands.rename "dir", "ls", :description => "DOS friendly ls"
    def rename_command(new_match, search, options={})
      cmd = find_command_by_match_or_listing(search)

      options = {
        :listing     => new_match,
        :description => cmd.description
      }.merge!(options)

      @commands[new_match] = cmd.dup
      @commands[new_match].match = new_match
      @commands[new_match].description = options.delete(:description)
      @commands[new_match].options.merge!(options)
      @commands.delete(cmd.match)
    end

    def disabled_command(name_of_disabled_command, message, matcher=name_of_disabled_command)
      create_command name_of_disabled_command do
        match matcher
        description ""

        define_method(:process) do
          output.puts "DISABLED: #{message}"
        end
      end
    end

    # Sets or gets the description for a command (replacing the old
    # description). Returns current description if no description
    # parameter provided.
    # @param [String, Regexp] search The command match.
    # @param [String?] description (nil) The command description.
    # @example Setting
    #   MyCommands = Pry::CommandSet.new do
    #     desc "help", "help description"
    #   end
    # @example Getting
    #   Pry.config.commands.desc "amend-line"
    def desc(search, description=nil)
      cmd = find_command_by_match_or_listing(search)
      return cmd.description if !description

      cmd.description = description
    end

    # Defines helpers methods for this command sets.
    # Those helpers are only defined in this command set.
    #
    # @yield A block defining helper methods
    # @example
    #   helpers do
    #     def hello
    #       puts "Hello!"
    #     end
    #
    #     include OtherModule
    #   end
    def helpers(&block)
      helper_module.class_eval(&block)
    end


    # @return [Array]
    #   The list of commands provided by the command set.
    def list_commands
      @commands.keys
    end
    alias_method :keys, :list_commands

    def to_hash
      @commands.dup
    end
    alias_method :to_h, :to_hash

    # Find a command that matches the given line
    # @param [String] pattern The line that might be a command invocation
    # @return [Pry::Command, nil]
    def [](pattern)
      @commands.values.select do |command|
        command.matches?(pattern)
      end.sort_by do |command|
        command.match_score(pattern)
      end.last
    end
    alias_method :find_command, :[]

    #
    # Re-assign the command found at _pattern_ with _command_.
    #
    # @param [Regexp, String] pattern
    #   The command to add or replace(found at _pattern_).
    #
    # @param [Pry::Command] command
    #   The command to add.
    #
    # @return [Pry::Command]
    #   Returns the new command (matched with "pattern".)
    #
    # @example
    #   Pry.config.commands["help"] = MyHelpCommand
    #
    def []=(pattern, command)
      if command.equal?(nil)
        return @commands.delete(pattern)
      end
      unless Class === command && command < Pry::Command
        raise TypeError, "command is not a subclass of Pry::Command"
      end
      bind_command_to_pattern = pattern != command.match
      if bind_command_to_pattern
        command_copy = command.dup
        command_copy.match = pattern
        @commands[pattern] = command_copy
      else
        @commands[pattern] = command
      end
    end

    #
    # Add a command to set.
    #
    # @param [Command] command
    #   a subclass of Pry::Command.
    #
    def add_command(command)
      self[command.match] = command
    end

    # Find the command that the user might be trying to refer to.
    # @param [String] search The user's search.
    # @return [Pry::Command?]
    def find_command_for_help(search)
      find_command(search) || (begin
        find_command_by_match_or_listing(search)
      rescue ArgumentError
        nil
      end)
    end

    # Is the given line a command invocation?
    # @param [String] val
    # @return [Boolean]
    def valid_command?(val)
      !!find_command(val)
    end

    # Process the given line to see whether it needs executing as a command.
    # @param [String] val The line to execute
    # @param [Hash] context The context to execute the commands with
    # @return [CommandSet::Result]
    def process_line(val, context={})
      if command = find_command(val)
        context = context.merge(:command_set => self)
        retval = command.new(context).process_line(val)
        Result.new(true, retval)
      else
        Result.new(false)
      end
    end

    # @private (used for testing)
    def run_command(context, match, *args)
      command = @commands[match] or raise NoCommandError.new(match, self)
      command.new(context).call_safely(*args)
    end

    # Generate completions for the user's search.
    # @param [String] search The line to search for
    # @param [Hash] context  The context to create the command with
    # @return [Array<String>]
    def complete(search, context={})
      if command = find_command(search)
        command.new(context).complete(search)
      else
        @commands.keys.select do |key|
          String === key && key.start_with?(search)
        end.map{ |key| key + " " }
      end
    end
  end

  # Wraps the return result of process_commands, indicates if the
  # result IS a command and what kind of command (e.g void)
  class Result
    attr_reader :retval

    def initialize(is_command, retval = nil)
      @is_command, @retval = is_command, retval
    end

    # Is the result a command?
    # @return [Boolean]
    def command?
      @is_command
    end

    # Is the result a command and if it is, is it a void command?
    # (one that does not return a value)
    # @return [Boolean]
    def void_command?
      retval == Command::VOID_VALUE
    end
  end
end
