module Msf::DBManager::Activation::Once
  extend ActiveSupport::Concern

  #
  # CONSTANTS
  #

  # The adapter to use to establish database connection.
  ADAPTER = 'postgresql'

  included do
    include ActiveModel::Validations

    #
    # Validations
    #

    validate :no_adapter_activation_error
  end

  #
  # Attributes
  #

  # @!attribute [r] activated_once?
  #   Whether {#activate_once} has completed already.
  #
  #   @return [Boolean]

  # @!attribute [r] adapter_activation_error
  #   Error raised by {#activate_adapter_once}
  #
  #   @return [nil] if no error
  #   @return [Exception] if {ADAPTER} could not establish a connection.

  #
  # Methods
  #

  # Whether {#activate_once} has completed.
  #
  # @return [true] when {#activate_once} has completed one time.
  # @return [false] when {#activate_once} has not completed yet or has not been called.
  def activated_once?
    # force `nil` (when undefined) to `false`
    !!@activated_once
  end

  # Methods that only need to run once because they require/load code or set globals/constants that are not (or cannot)
  # be unset.
  #
  # @return [void]
  def activate_once
    # if already activated once, then skip the synchronize.  @actived_once transitions from undefined to `true` and
    # instance variable reads are thread-safe so, don't take the cost of synchronize if already `true`.
    # thread-safety of instance variable read is proven by
    # https://github.com/ruby/ruby/blob/727d746eaa6389c6992d72318ec004d2681a2efc/lib/monitor.rb#L184 where
    # @mon_owner can be read and @mon_mutex only needs to locked to write to @mon_owner.
    unless activated_once?
      synchronize do
        # check again once in synchronized block in case the {#activate_once} completed between when we checked outside
        # synchronize and when the lock was acquired.
        unless activated_once?
          require 'active_record'

          activate_metasploit_data_models_once
          activate_adapter_once

          # write inside synchronize as only reads are safe outside synchronize
          @activated_once = true
        end
      end
    end
  end

  # Error raised by {#activate_adapter_once}.
  #
  # @return [nil] if no error
  # @return [Exception] if {ADAPTER} could not establish a connection.
  def adapter_activation_error
    # just call activate_once once as it will handle setting @adapter_activation_error in a thread-safe manner.
    activate_once

    @adapter_activation_error
  end

  private

  # @note Should only be run once by {#activate_once}.
  #
  # Attempts to activate postgresql driver.
  #
  # @return [void]
  def activate_adapter_once
    ActiveRecord::Base.default_timezone = :utc

    if ActiveRecord::Base.connected? && ActiveRecord::Base.connection_config[:adapter] == ADAPTER
      dlog("Already connected to #{ADAPTER}, so reusing active connection.")
    else
      begin
        ActiveRecord::Base.establish_connection(adapter: ADAPTER)
        ActiveRecord::Base.remove_connection
      rescue Exception => error
        @adapter_activation_error = error
      end
    end
  end

  # @note Should only be run once by {#activate_once}.
  #
  # Loads Metasploit Data Models and adds its migrations to migrations paths.
  #
  # @return [void]
  def activate_metasploit_data_models_once
    # Provide access to ActiveRecord models shared w/ commercial versions
    require "metasploit_data_models"

    metasploit_data_model_migrations_pathname = MetasploitDataModels.root.join(
        'db',
        'migrate'
    )
    metasploit_data_model_migrations_path = metasploit_data_model_migrations_pathname.to_path

    # Since ActiveRecord::Migrator.migrations_paths can persist between
    # instances of Msf::DBManager, such as in specs,
    # metasploit_data_models_migrations_path may already be part of
    # migrations_paths, in which case it should not be added or multiple
    # migrations with the same version number errors will occur.
    unless ActiveRecord::Migrator.migrations_paths.include? metasploit_data_model_migrations_path
      ActiveRecord::Migrator.migrations_paths << metasploit_data_model_migrations_path
    end
  end

  # @note Runs {#activate_once}, but {#activate_once} only does work if not already run.
  #
  # Validates there was no {#adapter_activation_error} in {#activate_adapter_once}.  If there was an
  # {#adapter_activation_error}, then it becomes a validation error on :adapter.
  #
  # @return [void]
  def no_adapter_activation_error
    if adapter_activation_error
      # use @adapter_activation_error to skip overhead of checking if activated once again.
      errors[:adapter] << @adapter_activation_error.to_s
    end
  end
end