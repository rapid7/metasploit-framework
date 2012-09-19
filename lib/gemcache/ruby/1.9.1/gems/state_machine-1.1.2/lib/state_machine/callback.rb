require 'state_machine/branch'
require 'state_machine/eval_helpers'

module StateMachine
  # Callbacks represent hooks into objects that allow logic to be triggered
  # before, after, or around a specific set of transitions.
  class Callback
    include EvalHelpers
    
    class << self
      # Determines whether to automatically bind the callback to the object
      # being transitioned.  This only applies to callbacks that are defined as
      # lambda blocks (or Procs).  Some integrations, such as DataMapper, handle
      # callbacks by executing them bound to the object involved, while other
      # integrations, such as ActiveRecord, pass the object as an argument to
      # the callback.  This can be configured on an application-wide basis by
      # setting this configuration to +true+ or +false+.  The default value
      # is +false+.
      # 
      # *Note* that the DataMapper and Sequel integrations automatically
      # configure this value on a per-callback basis, so it does not have to
      # be enabled application-wide.
      # 
      # == Examples
      # 
      # When not bound to the object:
      # 
      #   class Vehicle
      #     state_machine do
      #       before_transition do |vehicle|
      #         vehicle.set_alarm
      #       end
      #     end
      #     
      #     def set_alarm
      #       ...
      #     end
      #   end
      # 
      # When bound to the object:
      # 
      #   StateMachine::Callback.bind_to_object = true
      #   
      #   class Vehicle
      #     state_machine do
      #       before_transition do
      #         self.set_alarm
      #       end
      #     end
      #     
      #     def set_alarm
      #       ...
      #     end
      #   end
      attr_accessor :bind_to_object
      
      # The application-wide terminator to use for callbacks when not
      # explicitly defined.  Terminators determine whether to cancel a
      # callback chain based on the return value of the callback.
      # 
      # See StateMachine::Callback#terminator for more information.
      attr_accessor :terminator
    end
    
    # The type of callback chain this callback is for.  This can be one of the
    # following:
    # * +before+
    # * +after+
    # * +around+
    # * +failure+
    attr_accessor :type
    
    # An optional block for determining whether to cancel the callback chain
    # based on the return value of the callback.  By default, the callback
    # chain never cancels based on the return value (i.e. there is no implicit
    # terminator).  Certain integrations, such as ActiveRecord and Sequel,
    # change this default value.
    # 
    # == Examples
    # 
    # Canceling the callback chain without a terminator:
    # 
    #   class Vehicle
    #     state_machine do
    #       before_transition do |vehicle|
    #         throw :halt
    #       end
    #     end
    #   end
    # 
    # Canceling the callback chain with a terminator value of +false+:
    # 
    #   class Vehicle
    #     state_machine do
    #       before_transition do |vehicle|
    #         false
    #       end
    #     end
    #   end
    attr_reader :terminator
    
    # The branch that determines whether or not this callback can be invoked
    # based on the context of the transition.  The event, from state, and
    # to state must all match in order for the branch to pass.
    # 
    # See StateMachine::Branch for more information.
    attr_reader :branch
    
    # Creates a new callback that can get called based on the configured
    # options.
    # 
    # In addition to the possible configuration options for branches, the
    # following options can be configured:
    # * <tt>:bind_to_object</tt> - Whether to bind the callback to the object involved.
    #   If set to false, the object will be passed as a parameter instead.
    #   Default is integration-specific or set to the application default.
    # * <tt>:terminator</tt> - A block/proc that determines what callback
    #   results should cause the callback chain to halt (if not using the
    #   default <tt>throw :halt</tt> technique).
    # 
    # More information about how those options affect the behavior of the
    # callback can be found in their attribute definitions.
    def initialize(type, *args, &block)
      @type = type
      raise ArgumentError, 'Type must be :before, :after, :around, or :failure' unless [:before, :after, :around, :failure].include?(type)
      
      options = args.last.is_a?(Hash) ? args.pop : {}
      @methods = args
      @methods.concat(Array(options.delete(:do)))
      @methods << block if block_given?
      raise ArgumentError, 'Method(s) for callback must be specified' unless @methods.any?
      
      options = {:bind_to_object => self.class.bind_to_object, :terminator => self.class.terminator}.merge(options)
      
      # Proxy lambda blocks so that they're bound to the object
      bind_to_object = options.delete(:bind_to_object)
      @methods.map! do |method|
        bind_to_object && method.is_a?(Proc) ? bound_method(method) : method
      end
      
      @terminator = options.delete(:terminator)
      @branch = Branch.new(options)
    end
    
    # Gets a list of the states known to this callback by looking at the
    # branch's known states
    def known_states
      branch.known_states
    end
    
    # Runs the callback as long as the transition context matches the branch
    # requirements configured for this callback.  If a block is provided, it
    # will be called when the last method has run.
    # 
    # If a terminator has been configured and it matches the result from the
    # evaluated method, then the callback chain should be halted.
    def call(object, context = {}, *args, &block)
      if @branch.matches?(object, context)
        run_methods(object, context, 0, *args, &block)
        true
      else
        false
      end
    end
    
    private
      # Runs all of the methods configured for this callback.
      # 
      # When running +around+ callbacks, this will evaluate each method and
      # yield when the last method has yielded.  The callback will only halt if
      # one of the methods does not yield.
      # 
      # For all other types of callbacks, this will evaluate each method in
      # order.  The callback will only halt if the resulting value from the
      # method passes the terminator.
      def run_methods(object, context = {}, index = 0, *args, &block)
        if type == :around
          if method = @methods[index]
            yielded = false
            evaluate_method(object, method, *args) do
              yielded = true
              run_methods(object, context, index + 1, *args, &block)
            end
            
            throw :halt unless yielded
          else
            yield if block_given?
          end
        else
          @methods.each do |method|
            result = evaluate_method(object, method, *args)
            throw :halt if @terminator && @terminator.call(result)
          end
        end
      end
      
      # Generates a method that can be bound to the object being transitioned
      # when the callback is invoked
      def bound_method(block)
        type = self.type
        arity = block.arity
        arity += 1 if arity >= 0 # Make sure the object gets passed
        arity += 1 if arity == 1 && type == :around  # Make sure the block gets passed
        
        method = if RUBY_VERSION >= '1.9'
          lambda do |object, *args|
            object.instance_exec(*args, &block)
          end
        else
          # Generate a thread-safe unbound method that can be used on any object.
          # This is a workaround for not having Ruby 1.9's instance_exec
          unbound_method = Object.class_eval do
            time = Time.now
            method_name = "__bind_#{time.to_i}_#{time.usec}"
            define_method(method_name, &block)
            method = instance_method(method_name)
            remove_method(method_name)
            method
          end
          
          # Proxy calls to the method so that the method can be bound *and*
          # the arguments are adjusted
          lambda do |object, *args|
            unbound_method.bind(object).call(*args)
          end
        end
        
        # Proxy arity to the original block
        (class << method; self; end).class_eval do
          define_method(:arity) { arity }
        end
        
        method
      end
  end
end
