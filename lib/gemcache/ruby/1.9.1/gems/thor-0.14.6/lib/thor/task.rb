class Thor
  class Task < Struct.new(:name, :description, :long_description, :usage, :options)
    FILE_REGEXP = /^#{Regexp.escape(File.dirname(__FILE__))}/

    def initialize(name, description, long_description, usage, options=nil)
      super(name.to_s, description, long_description, usage, options || {})
    end

    def initialize_copy(other) #:nodoc:
      super(other)
      self.options = other.options.dup if other.options
    end

    def hidden?
      false
    end

    # By default, a task invokes a method in the thor class. You can change this
    # implementation to create custom tasks.
    def run(instance, args=[])
      public_method?(instance) ?
        instance.send(name, *args) : instance.class.handle_no_task_error(name)
    rescue ArgumentError => e
      handle_argument_error?(instance, e, caller) ?
        instance.class.handle_argument_error(self, e) : (raise e)
    rescue NoMethodError => e
      handle_no_method_error?(instance, e, caller) ?
        instance.class.handle_no_task_error(name) : (raise e)
    end

    # Returns the formatted usage by injecting given required arguments
    # and required options into the given usage.
    def formatted_usage(klass, namespace = true, subcommand = false)
      if namespace
        namespace = klass.namespace
        formatted = "#{namespace.gsub(/^(default)/,'')}:"
        formatted.sub!(/.$/, ' ') if subcommand
      end

      formatted ||= ""

      # Add usage with required arguments
      formatted << if klass && !klass.arguments.empty?
        usage.to_s.gsub(/^#{name}/) do |match|
          match << " " << klass.arguments.map{ |a| a.usage }.compact.join(' ')
        end
      else
        usage.to_s
      end

      # Add required options
      formatted << " #{required_options}"

      # Strip and go!
      formatted.strip
    end

  protected

    def not_debugging?(instance)
      !(instance.class.respond_to?(:debugging) && instance.class.debugging)
    end

    def required_options
      @required_options ||= options.map{ |_, o| o.usage if o.required? }.compact.sort.join(" ")
    end

    # Given a target, checks if this class name is not a private/protected method.
    def public_method?(instance) #:nodoc:
      collection = instance.private_methods + instance.protected_methods
      (collection & [name.to_s, name.to_sym]).empty?
    end

    def sans_backtrace(backtrace, caller) #:nodoc:
      saned  = backtrace.reject { |frame| frame =~ FILE_REGEXP }
      saned -= caller
    end

    def handle_argument_error?(instance, error, caller)
      not_debugging?(instance) && error.message =~ /wrong number of arguments/ && begin
        saned = sans_backtrace(error.backtrace, caller)
        # Ruby 1.9 always include the called method in the backtrace
        saned.empty? || (saned.size == 1 && RUBY_VERSION >= "1.9")
      end
    end

    def handle_no_method_error?(instance, error, caller)
      not_debugging?(instance) &&
        error.message =~ /^undefined method `#{name}' for #{Regexp.escape(instance.to_s)}$/
    end
  end

  # A task that is hidden in help messages but still invocable.
  class HiddenTask < Task
    def hidden?
      true
    end
  end

  # A dynamic task that handles method missing scenarios.
  class DynamicTask < Task
    def initialize(name, options=nil)
      super(name.to_s, "A dynamically-generated task", name.to_s, name.to_s, options)
    end

    def run(instance, args=[])
      if (instance.methods & [name.to_s, name.to_sym]).empty?
        super
      else
        instance.class.handle_no_task_error(name)
      end
    end
  end
end
