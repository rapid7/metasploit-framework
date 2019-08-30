module Msf::Module::Alert
  # This mixin provides a way for alert messages to be added to module classes
  # and instances, retrieved from module classes and instances, and displayed
  # from module instances. The two alert levels provided by this mixin are
  # `:error` and `:warning`, though other levels or display methods can be
  # added by subclasses/other mixins if desired by overriding {#alert_user}
  # method (calling `super` as necessary), adding a proxy method like
  # {ClassMethods#add_warning} that calls {ClassMethods#add_alert} or
  # {#add_alert} and optionally a helper retrieval method like
  # {ClassMethods#warnings}.

  module ClassMethods
    # Add a warning that will be provided to the user as early possible when
    # using the module, either when they select it with the `use` command, when
    # the module is about to start running, or when the module generates its
    # output.
    #
    # @param msg [String] an optional warning message 
    # @param block [Proc] an optional block that will be executed in the
    #   context of the module instance at alert time to generate the warning
    #   message. If provided the msg parameter is ignored.
    # @return [true, nil] whether or not the message was added to the list of
    #   warnings
    def add_warning(msg = nil, &block)
      add_alert(:warning, msg, &block)
    end

    # Add an error that will be provided to the user as early possible when
    # using the module, either when they select it with the `use` command, when
    # the module is about to start running, or when the module generates its
    # output. Adding an error will cause {#is_usable} to return `false`.
    #
    # @param msg [String] an optional error message 
    # @param block [Proc] an optional block that will be executed in the
    #   context of the module instance at alert time to generate the error
    #   message. If provided the msg parameter is ignored.
    # @return [true, nil] whether or not the message was added to the list of
    #   errors
    def add_error(msg = nil, &block)
      add_alert(:error, msg, &block)
    end

    # @return [Array<String, Proc>] a list of warning message strings, or
    #   blocks (see #get_alerts)
    def warnings
      get_alerts(:warning)
    end

    # @return [Array<String, Proc>] a list of error message strings, or
    #   blocks (see #get_alerts)
    def errors
      get_alerts(:error)
    end

    # @param [Symbol] the alert level to return
    # @return [Array<String, Proc>] a list of `level` alerts, either in string
    #   or block form. Blocks expect to be executed in the context of a fully
    #   initialized module instance and will return `nil` if the alert they are
    #   looking for does not apply or a string or array of strings, each
    #   representing an alert.
    def get_alerts(level)
      # Initialize here if needed, thanks to weird metaprogramming side-effects
      self.alerts ||= {}
      self.alerts[level] || []
    end

    # This method allows modules to tell the framework if they are usable
    # on the system that they are being loaded on in a generic fashion.
    # By default, all modules are indicated as being usable.  An example of
    # where this is useful is if the module depends on something external to
    # ruby, such as a binary.
    #
    # This looks to have been abandoned at some point in the past, but it may
    # be time to resurrect it.
    #
    # @return [true, false] whether or not the module has encountered any fatal
    #   errors thus far.
    def usable?
      errors.empty?
    end

    protected

    attr_accessor :alerts

    # Add a message (or block that generates messages) to a module. This
    # message will be displayed once to the user by every instance of this
    # module.
    def add_alert(level, msg, &block)
      self.alerts ||= {}
      self.alerts[level] ||= []
      if block
        self.alerts[level] << block
        true
      elsif msg
        self.alerts[level] << msg
        true
      end
    end
  end

  # @nodoc
  def self.included(base)
    base.extend(ClassMethods)
  end

  # Add a warning that will be provided to the user as early possible when
  # using this instance of a module, either when they select it with the `use`
  # command, when the module is about to start running, or when the module
  # generates its output.
  #
  # @param msg [String] an optional warning message 
  # @param block [Proc] an optional block that will be executed in the
  #   context of the module instance at alert time to generate the warning
  #   message. If provided the msg parameter is ignored.
  # @return [true, nil] whether or not the message was added to the list of
  #   warnings
  def add_warning(msg = nil, &block)
    add_alert(:warning, msg, &block)
  end

  # Add a error that will be provided to the user as early possible when using
  # this instance of a  module, either when they select it with the `use`
  # command, when the module is about to start running, or when the module
  # generates its output. Adding an error will cause {#is_usable} to return
  # `false`.
  #
  # @param msg [String] an optional error message 
  # @param block [Proc] an optional block that will be executed in the
  #   context of the module instance at alert time to generate the error
  #   message. If provided the msg parameter is ignored.
  # @return [true, nil] whether or not the message was added to the list of
  #   errors
  def add_error(msg = nil, &block)
    add_alert(:error, msg, &block)
  end

  # This method allows modules to tell the framework if they are usable
  # on the system that they are being loaded on in a generic fashion.
  # By default, all modules are indicated as being usable.  An example of
  # where this is useful is if the module depends on something external to
  # ruby, such as a binary.
  #
  # This looks to have been abandoned at some point in the past, but it may
  # be time to resurrect it.
  #
  # @return [true, false] whether or not the module has encountered any fatal
  #   errors thus far.
  def is_usable?
    errors.empty?
  end

  # @return [Array<String>] a list of warning strings to show the user
  def warnings
    get_alerts(:warning)
  end

  # @return [Array<String>] a list of error strings to show the user
  def errors
    get_alerts(:error)
  end

  # Similar to {ClassMethods#get_alerts}, but executes each registered block in
  # the context of this module instance and returns a flattened list of strings.
  # (see {ClassMethods#get_alerts})
  # @param [Symbol] the alert level to return
  # @return [Array<String>] 
  def get_alerts(level)
    self.alerts ||= {}
    self.alerts[level] ||= []
    all_alerts = self.class.get_alerts(level) + self.alerts[level]
    all_alerts.map do |alert|
      case alert
      when Proc
        self.instance_exec &alert
      else
        alert
      end
    end.flatten.compact
  end

  protected

  attr_accessor :alerts, :you_have_been_warned

  # Add an alert for _this instance_ of a module (see {ClassMethods#add_alert})
  def add_alert(level, msg, &block)
    self.alerts ||= {}
    self.alerts[level] ||= []
    if block
      self.alerts[level] << block
      true
    elsif msg
      self.alerts[level] << msg
      true
    end
  end

  # Display alerts with `print_warning` for warnings and `print_error` for
  # errors. Alerts that have already been displayed by this module instance
  # with this method will not be displayed again.
  def alert_user
    self.you_have_been_warned ||= {}

    errors.each do |msg|
      if msg && !self.you_have_been_warned[msg.hash]
        print_error(msg)
        self.you_have_been_warned[msg.hash] = true
      end
    end

    warnings.each do |msg|
      if msg && !self.you_have_been_warned[msg.hash]
        print_warning(msg)
        self.you_have_been_warned[msg.hash] = true
      end
    end
  end
end
