# -*- coding: binary -*-

# This class manages the threads spawned by the framework object, this provides some additional
# features over standard ruby threads.
#
# @example Safe initialization and validations
#   thread_manager = Metasploit::Framework::Thread::Manager.new(framework: framework)
#   # valid! is synchronized
#   thread_manager.valid!
#
#   # valid? is not synchronized
#   thread_manager.synchronize {
#     unless thread_manager.valid?
#       puts thread_manager.errors.full_messages
#     end
#   }
class Metasploit::Framework::Thread::Manager < Metasploit::Model::Base
  include MonitorMixin

  require 'metasploit/framework/thread/manager/already_registered'

  #
  # Attributes
  #

  # @!attribute [rw] framework
  #  The framework for which this thread manager is managing threads.  Used to ensure that Database connections are
  #  cleaned up when an exception occurs in a `Thread`.
  #
  #  @return [Msf::Simple::Framework]

  #
  # Validations
  #

  validates :framework,
            presence: true

  #
  # Methods
  #

  def framework
    synchronize {
      @framework
    }
  end

  def framework=(framework)
    synchronize {
      @framework = framework
    }
  end

  # @param attributes [Hash{Symbol => Object}]
  # @option attributes [Msf::Simple::Framework] framework Framework that is using
  def initialize(attributes={})
    # mon_initialize is called at the end of MonitorMixin#initialize, so can't use Metasploit::Model::Base#initialize to
    # set {#framework}, which uses MonitorMixin#synchronize, which needs mon_initialize to run first.
    @framework = attributes[:framework]

    # Call super() to call #mon_initialize, but no set attributes in Metasploit::Mode::Base#initialize.
    super()
  end

  # Since `ThreadGroup#list` is a C-function in MRI I'm assuming that it does not need to be synchronized with
  # `ThreadGroup#add`.
  delegate :list,
           to: :thread_group

  def valid!
    synchronize {
      super
    }
  end

  # @note Other threads should have already been {#spawn spawned} before registering the current thread, or as register
  #   will block.
  #
  # Registers the current thread with this thread manager.
  #
  # @param attributes [Hash{Symbol => Object}]
  # @option attributes [Array<String>] :backtrace (caller) for the where the current Thread was spawned.
  # @option attributes [Proc] :block The block to run for the remainder of the time the current Thread is registered.
  # @option attributes [Array] :block_arguments Arguments passed to :block or &block.
  # @option attributes [Boolean] :critical Whether this thread is critical and should not be killed when mass-culling
  #   managed threads.
  # @option attributes [String] :name Name of this thread.  Used to kill the thread in {#list} and display its status.
  # @yield [*block_arguments] Calls block
  # @y
  # @return [Object] yieldreturn
  # @raise [Metasploiit::Model::Invalid] if
  def register(attributes={}, &block)
    metasploit_framework_thread = Thread.current[:metasploit_framework_thread]

    if metasploit_framework_thread
      raise Metasploit::Framework::Thread::Manager::AlreadyRegistered.new(metasploit_framework_thread)
    end

    unless attributes[:backtrace]
      attributes = attributes.merge(
          backtrace: caller
      )
    end

    unless attributes[:spawned_at]
      attributes = attributes.merge(
          spawned_at: Time.now
      )
    end

    metasploit_framework_thread = Metasploit::Framework::Thread.new(attributes, &block)
    metasploit_framework_thread.valid!

    # Set before adding to {#thread_group} so no Thread in {#thread_group} does not have this thread local variable.
    Thread.current[:metasploit_framework_thread] = metasploit_framework_thread

    old_thread_group = Thread.current.group
    # add to thread_group only after setting :metasploit_framework_thread so {#list} only contains Threads with
    # :metasploit_framework_thread
    thread_group.add Thread.current

    begin
      value = metasploit_framework_thread.run
    rescue Exception => error
      metasploit_framework_thread.log_and_raise error
    ensure
      # no connection release ensure like in #spawn because the current thread may persist if error is rescued higher
      # up, so no way to know if connection should be released here

      # remove from group before deleting thread local variable to maintain invariant.
      old_thread_group.add Thread.current
      # deregister so thread can be re-registered
      Thread.current[:metasploit_framework_thread] = nil
    end

    value
  end

  # Whether the current thread is already {#register registered}.
  #
  # @return [Boolean]
  def registered?
    !Thread.current[:metasploit_framework_thread].nil?
  end

    # Spawns a new thread.
  #
  # @param name [String] name to assign to the thread.  The name is used to kill the thread in various APIs in the
  #   framework.
  # @param critical [Boolean] whether this thread is critical to the operation of the framework and should not be killed
  #   when mass culling threads with certain commands.
  # @param block_arguments [Array<Object>] arguments to pass to `block`.
  # @yield [*block_arguments] Block receives all arguments passed after `critical` and before the `block`.
  # @yieldreturn [void]
  # @return [Thread]
  def spawn(name, critical, *block_arguments, &block)
    # have the spawn time be before Thread.new in case it takes awhile for the thread to wake up.
    spawned_at = Time.now

    thread = Thread.new {
      begin
        register(
            block: block,
            block_arguments: block_arguments,
            critical: critical,
            name: name,
            spawned_at: spawned_at
        )
      ensure
        # Remove connections since this thread is dead, unlike with {#register} where it may live on.
        # DO NOT use {Msf::DBManager#with_connection} as it will just end up checking out a connection and the whole
        # point of this is to clean up connections from the `block`.
        if framework.db.connected?
          # NOTE: despite the Deprecation Warning's advice, this should *NOT*
          # be ActiveRecord::Base.connection.close which causes unrelated
          # threads to raise ActiveRecord::StatementInvalid exceptions at
          # some point in the future, presumably due to the pool manager
          # believing that the connection is still usable and handing it out
          # to another thread.
          ActiveRecord::Base.connection_pool.release_connection
        end
      end
    }

    # @note If it takes awhile for the thread to wake up, it may be not in thread_group right-away, but if the thread
    #   is not in the thread_group yet, then thread_group.list

    thread
  end

  private

  # Group of threads either {#spawn spawned by} or {#register registered to} this thread manager.
  #
  # @return [ThreadGroup]
  def thread_group
    synchronize {
      @thread_group ||= ThreadGroup.new
    }
  end
end
