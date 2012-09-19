class Thor
  module Invocation
    def self.included(base) #:nodoc:
      base.extend ClassMethods
    end

    module ClassMethods
      # This method is responsible for receiving a name and find the proper
      # class and task for it. The key is an optional parameter which is
      # available only in class methods invocations (i.e. in Thor::Group).
      def prepare_for_invocation(key, name) #:nodoc:
        case name
        when Symbol, String
          Thor::Util.find_class_and_task_by_namespace(name.to_s, !key)
        else
          name
        end
      end
    end

    # Make initializer aware of invocations and the initialization args.
    def initialize(args=[], options={}, config={}, &block) #:nodoc:
      @_invocations = config[:invocations] || Hash.new { |h,k| h[k] = [] }
      @_initializer = [ args, options, config ]
      super
    end

    # Receives a name and invokes it. The name can be a string (either "task" or
    # "namespace:task"), a Thor::Task, a Class or a Thor instance. If the task
    # cannot be guessed by name, it can also be supplied as second argument.
    #
    # You can also supply the arguments, options and configuration values for
    # the task to be invoked, if none is given, the same values used to
    # initialize the invoker are used to initialize the invoked.
    #
    # When no name is given, it will invoke the default task of the current class.
    #
    # ==== Examples
    #
    #   class A < Thor
    #     def foo
    #       invoke :bar
    #       invoke "b:hello", ["José"]
    #     end
    #
    #     def bar
    #       invoke "b:hello", ["José"]
    #     end
    #   end
    #
    #   class B < Thor
    #     def hello(name)
    #       puts "hello #{name}"
    #     end
    #   end
    #
    # You can notice that the method "foo" above invokes two tasks: "bar",
    # which belongs to the same class and "hello" which belongs to the class B.
    #
    # By using an invocation system you ensure that a task is invoked only once.
    # In the example above, invoking "foo" will invoke "b:hello" just once, even
    # if it's invoked later by "bar" method.
    #
    # When class A invokes class B, all arguments used on A initialization are
    # supplied to B. This allows lazy parse of options. Let's suppose you have
    # some rspec tasks:
    #
    #   class Rspec < Thor::Group
    #     class_option :mock_framework, :type => :string, :default => :rr
    #
    #     def invoke_mock_framework
    #       invoke "rspec:#{options[:mock_framework]}"
    #     end
    #   end
    #
    # As you noticed, it invokes the given mock framework, which might have its
    # own options:
    #
    #   class Rspec::RR < Thor::Group
    #     class_option :style, :type => :string, :default => :mock
    #   end
    #
    # Since it's not rspec concern to parse mock framework options, when RR
    # is invoked all options are parsed again, so RR can extract only the options
    # that it's going to use.
    #
    # If you want Rspec::RR to be initialized with its own set of options, you
    # have to do that explicitly:
    #
    #   invoke "rspec:rr", [], :style => :foo
    #
    # Besides giving an instance, you can also give a class to invoke:
    #
    #   invoke Rspec::RR, [], :style => :foo
    #
    def invoke(name=nil, *args)
      if name.nil?
        warn "[Thor] Calling invoke() without argument is deprecated. Please use invoke_all instead.\n#{caller.join("\n")}"
        return invoke_all
      end

      args.unshift(nil) if Array === args.first || NilClass === args.first
      task, args, opts, config = args

      klass, task = _retrieve_class_and_task(name, task)
      raise "Expected Thor class, got #{klass}" unless klass <= Thor::Base

      args, opts, config = _parse_initialization_options(args, opts, config)
      klass.send(:dispatch, task, args, opts, config) do |instance|
        instance.parent_options = options
      end
    end

    # Invoke the given task if the given args.
    def invoke_task(task, *args) #:nodoc:
      current = @_invocations[self.class]

      unless current.include?(task.name)
        current << task.name
        task.run(self, *args)
      end
    end

    # Invoke all tasks for the current instance.
    def invoke_all #:nodoc:
      self.class.all_tasks.map { |_, task| invoke_task(task) }
    end

    # Invokes using shell padding.
    def invoke_with_padding(*args)
      with_padding { invoke(*args) }
    end

    protected

      # Configuration values that are shared between invocations.
      def _shared_configuration #:nodoc:
        { :invocations => @_invocations }
      end

      # This method simply retrieves the class and task to be invoked.
      # If the name is nil or the given name is a task in the current class,
      # use the given name and return self as class. Otherwise, call
      # prepare_for_invocation in the current class.
      def _retrieve_class_and_task(name, sent_task=nil) #:nodoc:
        case
        when name.nil?
          [self.class, nil]
        when self.class.all_tasks[name.to_s]
          [self.class, name.to_s]
        else
          klass, task = self.class.prepare_for_invocation(nil, name)
          [klass, task || sent_task]
        end
      end

      # Initialize klass using values stored in the @_initializer.
      def _parse_initialization_options(args, opts, config) #:nodoc:
        stored_args, stored_opts, stored_config = @_initializer

        args ||= stored_args.dup
        opts ||= stored_opts.dup

        config ||= {}
        config = stored_config.merge(_shared_configuration).merge!(config)

        [ args, opts, config ]
      end
  end
end
