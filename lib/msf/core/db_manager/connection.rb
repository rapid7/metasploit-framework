require 'active_support/core_ext/numeric/time'

module Msf::DBManager::Connection
  extend ActiveSupport::Concern

  #
  # CONSTANTS
  #

  # Number of connections in the connection pool.
  POOL = 75
  # How long to wait before closing a connection.
  WAIT_TIMEOUT = 5.minutes

  included do
    include ActiveModel::Validations

    #
    # Validations
    #

    validate :no_database_creation_error
  end

  #
  # Attributes
  #

  # @!attribute [r] database_creation_error
  #   Error raised in {#create_database}.
  #
  #   @return [nil] if no error
  #   @return [Exception] if database could not be created.
  attr_reader :database_creation_error

  #
  # Methods
  #

  # Connects this instance to a database
  #
  # @param options [Hash{Symbol,String => Object}]
  # @return [Boolean]
  def connect(options={})
    synchronize {
      unless connected?
        if valid?
          normalized_options = normalize_connect_options(options)

          if create_database(normalized_options)
            # Configure the database adapter
            # database was created using these options, so known good
            ActiveRecord::Base.establish_connection(normalized_options)

            if migrate
              # Set the default workspace
              self.workspace = self.default_workspace
            end
          end
        end
      end

      # call connected? again to be consistent with check all the dependencies
      connected?
    }
  end

  # Allows code to branch :with and :without {#connected?}.
  #
  # @param options [Hash{Symbol => Proc}]
  # @option options [Proc, nil] :with Block to call instead `ActiveRecord::Base.connection_pool.with_connection` when
  #   {#connected?} is `true`.  If `nil`, does not run anything when connected.
  # @option options [Proc, nil] :without Block to run when {#connected?} is `false`.  If `nil` does not run anything
  #   when not connected
  # @return [void]
  # @raise [ArgumentError] if `options` keys not :with or :without.
  def connection(options={})
    options.assert_valid_keys(:with, :without)

    if connected?
      with_block = options[:with]

      if with_block
        ActiveRecord::Base.connection_pool.with_connection do
          # call here so block doesn't need to accept connection
          with_block.call
        end
      end
    else
      without_block = options[:without]

      if without_block
        without_block.call
      end
    end
  end

  # Has {#connect} be called already and the connection is active.
  #
  # @return [true] if connection established and connection pool is connected and the migrations have run.
  # @return [false] otherwise
  def connected?
    # ActiveRecord::Base.connected? can be non-Boolean so ensure return value is Boolean with explicit value.
    if ActiveRecord::Base.connected? && ActiveRecord::Base.connection_pool.connected? && migrated?
      true
    else
      false
    end
  end

  # Disconnects a database connection
  #
  # @return [void]
  def disconnect
    begin
      ActiveRecord::Base.remove_connection
    rescue Exception => error
      elog("#{error.class} #{error}:\n#{error.backtrace.join("\n")}")
    end
  end

  # Runs the given block only when {#connected?} and inside `ActiveRecord::Base.connection_pool.with_connection`.
  #
  # @yield Passes block to `ActiveRecord::Base.connection_pool.with_connection` to ensure that connection does not
  #   stayed checkouted and assigned to the current thread.
  # @yieldreturn [Object] value to return from this method when {#connected?} `true`.
  # @return [Object] yieldreturn from `block` if {#connected?} `true`.
  # @return [nil] if `block` not run because {#connected?} `false`.
  #
  # @see #connection
  def with_connection(&block)
    connection(with: block)
  end

  private

  # Attempt to create the database.
  #
  # If the database already exists this will fail and we will continue on our
  # merry way, connecting anyway.  If it doesn't, we try to create it.  If
  # that fails, then it wasn't meant to be and the connect will raise a
  # useful exception so the user won't be in the dark; no need to raise
  # anything at all here.
  #
  # @param normalized_options [Hash] options returned by {#normalize_options}.
  # @return [void]
  def create_database(normalized_options)
    created = false

    # @see https://github.com/rails/rails/blob/2fcd13eff251ca9e1ff5cf6a13f72c18087daf60/activerecord/lib/active_record/railties/databases.rake#L84
    begin
      # Try to force a connection to be made to the database, if it succeeds
      # then we know we don't need to create it :)
      ActiveRecord::Base.establish_connection(normalized_options)

      # Do the checkout, checkin dance here to make sure this thread doesn't
      # hold on to a connection we don't need
      conn = ActiveRecord::Base.connection_pool.checkout
      ActiveRecord::Base.connection_pool.checkin(conn)
    rescue Exception => error
      database = normalized_options['database']
      ilog("Database doesn't exist #{database.inspect}, attempting to create it.")

      begin
        postgres_database_options = normalized_options.merge(
            'database' => 'postgres',
            'schema_search_path' => 'public'
        )
        ActiveRecord::Base.establish_connection(postgres_database_options)

        encoding = normalized_options['encoding'] || ENV['CHARSET'] || 'utf8'
        creation_options = normalized_options.merge(
            'encoding' => encoding
        )
        ActiveRecord::Base.create_database(database, creation_options)

        ActiveRecord::Base.establish_connection(normalized_options)
      rescue Exception => error
        @database_creation_error = error
        elog(
            "#{error.class} #{error}:\n" \
            "#{error.backtrace.join("\n")}\n" \
            "Couldn't create database for #{normalized_options.inspect}"
        )
      else
        created = true
      end
    else
      created = true
    end

    ActiveRecord::Base.remove_connection

    created
  end

  # Validates there was no {#database_creation_error} from the last call to {#connect}.  If there was an
  # {#database_creation_error}, then it becomes a validation error on :creation.
  #
  # @return [void]
  def no_database_creation_error
    if database_creation_error
      errors[:creation] << database_creation_error.to_s
    end
  end

  # Normalizes options for {#connect} to the correct type and set defaults if not value is given.
  #
  # @param options [Hash{String => Object}] unnormalized options
  # @option options
  # @return [Hash]
  def normalize_connect_options(options)
    normalized_options = options.dup

    port = options['port']

    if port
      normalized_options['port'] = port.to_i
    end

    pool = options['pool']

    if pool
      normalized_options['pool'] = pool.to_i
    else
      normalized_options['pool'] = POOL
    end

    wait_timeout = options['wait_timeout']

    if wait_timeout
      normalized_options['wait_timeout'] = wait_timeout.to_i
    else
      normalized_options['wait_timeout'] = WAIT_TIMEOUT
    end

    normalized_options
  end
end