require 'thor/base'

class Thor
  class << self
    # Sets the default task when thor is executed without an explicit task to be called.
    #
    # ==== Parameters
    # meth<Symbol>:: name of the defaut task
    #
    def default_task(meth=nil)
      case meth
        when :none
          @default_task = 'help'
        when nil
          @default_task ||= from_superclass(:default_task, 'help')
        else
          @default_task = meth.to_s
      end
    end

    # Registers another Thor subclass as a command.
    #
    # ==== Parameters
    # klass<Class>:: Thor subclass to register
    # command<String>:: Subcommand name to use
    # usage<String>:: Short usage for the subcommand
    # description<String>:: Description for the subcommand
    def register(klass, subcommand_name, usage, description, options={})
      if klass <= Thor::Group
        desc usage, description, options
        define_method(subcommand_name) { invoke klass }
      else
        desc usage, description, options
        subcommand subcommand_name, klass
      end
    end

    # Defines the usage and the description of the next task.
    #
    # ==== Parameters
    # usage<String>
    # description<String>
    # options<String>
    #
    def desc(usage, description, options={})
      if options[:for]
        task = find_and_refresh_task(options[:for])
        task.usage = usage             if usage
        task.description = description if description
      else
        @usage, @desc, @hide = usage, description, options[:hide] || false
      end
    end

    # Defines the long description of the next task.
    #
    # ==== Parameters
    # long description<String>
    #
    def long_desc(long_description, options={})
      if options[:for]
        task = find_and_refresh_task(options[:for])
        task.long_description = long_description if long_description
      else
        @long_desc = long_description
      end
    end

    # Maps an input to a task. If you define:
    #
    #   map "-T" => "list"
    #
    # Running:
    #
    #   thor -T
    #
    # Will invoke the list task.
    #
    # ==== Parameters
    # Hash[String|Array => Symbol]:: Maps the string or the strings in the array to the given task.
    #
    def map(mappings=nil)
      @map ||= from_superclass(:map, {})

      if mappings
        mappings.each do |key, value|
          if key.respond_to?(:each)
            key.each {|subkey| @map[subkey] = value}
          else
            @map[key] = value
          end
        end
      end

      @map
    end

    # Declares the options for the next task to be declared.
    #
    # ==== Parameters
    # Hash[Symbol => Object]:: The hash key is the name of the option and the value
    # is the type of the option. Can be :string, :array, :hash, :boolean, :numeric
    # or :required (string). If you give a value, the type of the value is used.
    #
    def method_options(options=nil)
      @method_options ||= {}
      build_options(options, @method_options) if options
      @method_options
    end

    # Adds an option to the set of method options. If :for is given as option,
    # it allows you to change the options from a previous defined task.
    #
    #   def previous_task
    #     # magic
    #   end
    #
    #   method_option :foo => :bar, :for => :previous_task
    #
    #   def next_task
    #     # magic
    #   end
    #
    # ==== Parameters
    # name<Symbol>:: The name of the argument.
    # options<Hash>:: Described below.
    #
    # ==== Options
    # :desc     - Description for the argument.
    # :required - If the argument is required or not.
    # :default  - Default value for this argument. It cannot be required and have default values.
    # :aliases  - Aliases for this option.
    # :type     - The type of the argument, can be :string, :hash, :array, :numeric or :boolean.
    # :banner   - String to show on usage notes.
    #
    def method_option(name, options={})
      scope = if options[:for]
        find_and_refresh_task(options[:for]).options
      else
        method_options
      end

      build_option(name, options, scope)
    end

    # Prints help information for the given task.
    #
    # ==== Parameters
    # shell<Thor::Shell>
    # task_name<String>
    #
    def task_help(shell, task_name)
      meth = normalize_task_name(task_name)
      task = all_tasks[meth]
      handle_no_task_error(meth) unless task

      shell.say "Usage:"
      shell.say "  #{banner(task)}"
      shell.say
      class_options_help(shell, nil => task.options.map { |_, o| o })
      if task.long_description
        shell.say "Description:"
        shell.print_wrapped(task.long_description, :ident => 2)
      else
        shell.say task.description
      end
    end

    # Prints help information for this class.
    #
    # ==== Parameters
    # shell<Thor::Shell>
    #
    def help(shell, subcommand = false)
      list = printable_tasks(true, subcommand)
      Thor::Util.thor_classes_in(self).each do |klass|
        list += klass.printable_tasks(false)
      end
      list.sort!{ |a,b| a[0] <=> b[0] }

      shell.say "Tasks:"
      shell.print_table(list, :ident => 2, :truncate => true)
      shell.say
      class_options_help(shell)
    end

    # Returns tasks ready to be printed.
    def printable_tasks(all = true, subcommand = false)
      (all ? all_tasks : tasks).map do |_, task|
        next if task.hidden?
        item = []
        item << banner(task, false, subcommand)
        item << (task.description ? "# #{task.description.gsub(/\s+/m,' ')}" : "")
        item
      end.compact
    end

    def subcommands
      @subcommands ||= from_superclass(:subcommands, [])
    end

    def subcommand(subcommand, subcommand_class)
      self.subcommands << subcommand.to_s
      subcommand_class.subcommand_help subcommand
      define_method(subcommand) { |*args| invoke subcommand_class, args }
    end

    # Extend check unknown options to accept a hash of conditions.
    #
    # === Parameters
    # options<Hash>: A hash containing :only and/or :except keys
    def check_unknown_options!(options={})
      @check_unknown_options ||= Hash.new
      options.each do |key, value|
        if value
          @check_unknown_options[key] = Array(value)
        else
          @check_unknown_options.delete(key)
        end
      end
      @check_unknown_options
    end

    # Overwrite check_unknown_options? to take subcommands and options into account.
    def check_unknown_options?(config) #:nodoc:
      options = check_unknown_options
      return false unless options

      task = config[:current_task]
      return true unless task

      name = task.name

      if subcommands.include?(name)
        false
      elsif options[:except]
        !options[:except].include?(name.to_sym)
      elsif options[:only]
        options[:only].include?(name.to_sym)
      else
        true
      end
    end

    protected

      # The method responsible for dispatching given the args.
      def dispatch(meth, given_args, given_opts, config) #:nodoc:
        meth ||= retrieve_task_name(given_args)
        task = all_tasks[normalize_task_name(meth)]

        if task
          args, opts = Thor::Options.split(given_args)
        else
          args, opts = given_args, nil
          task = Thor::DynamicTask.new(meth)
        end

        opts = given_opts || opts || []
        config.merge!(:current_task => task, :task_options => task.options)

        trailing = args[Range.new(arguments.size, -1)]
        new(args, opts, config).invoke_task(task, trailing || [])
      end

      # The banner for this class. You can customize it if you are invoking the
      # thor class by another ways which is not the Thor::Runner. It receives
      # the task that is going to be invoked and a boolean which indicates if
      # the namespace should be displayed as arguments.
      #
      def banner(task, namespace = nil, subcommand = false)
        "#{basename} #{task.formatted_usage(self, $thor_runner, subcommand)}"
      end

      def baseclass #:nodoc:
        Thor
      end

      def create_task(meth) #:nodoc:
        if @usage && @desc
          base_class = @hide ? Thor::HiddenTask : Thor::Task
          tasks[meth] = base_class.new(meth, @desc, @long_desc, @usage, method_options)
          @usage, @desc, @long_desc, @method_options, @hide = nil
          true
        elsif self.all_tasks[meth] || meth == "method_missing"
          true
        else
          puts "[WARNING] Attempted to create task #{meth.inspect} without usage or description. " <<
               "Call desc if you want this method to be available as task or declare it inside a " <<
               "no_tasks{} block. Invoked from #{caller[1].inspect}."
          false
        end
      end

      def initialize_added #:nodoc:
        class_options.merge!(method_options)
        @method_options = nil
      end

      # Retrieve the task name from given args.
      def retrieve_task_name(args) #:nodoc:
        meth = args.first.to_s unless args.empty?

        if meth && (map[meth] || meth !~ /^\-/)
          args.shift
        else
          nil
        end
      end

      # Receives a task name (can be nil), and try to get a map from it.
      # If a map can't be found use the sent name or the default task.
      def normalize_task_name(meth) #:nodoc:
        meth = map[meth.to_s] || meth || default_task
        meth.to_s.gsub('-','_') # treat foo-bar > foo_bar
      end

      def subcommand_help(cmd)
        desc "help [COMMAND]", "Describe subcommands or one specific subcommand"
        class_eval <<-RUBY
          def help(task = nil, subcommand = true); super; end
        RUBY
      end
  end

  include Thor::Base

  map HELP_MAPPINGS => :help

  desc "help [TASK]", "Describe available tasks or one specific task"
  def help(task = nil, subcommand = false)
    task ? self.class.task_help(shell, task) : self.class.help(shell, subcommand)
  end
end
