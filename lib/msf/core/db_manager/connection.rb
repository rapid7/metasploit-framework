module Msf::DBManager::Connection
  # Returns true if we are ready to load/store data
  def active
    # In a Rails test scenario there will be a connection established already, and it needs to be checked manually to see if a migration is required
    # This check normally happens in after_establish_connection, but that might not always get called - for instance during RSpec tests
    if Rails.env.test? && migrated.nil? && usable && connection_established?
      self.migrated = !needs_migration?
    end

    # usable and migrated a just Boolean attributes, so check those first because they don't actually contact the
    # database.
    usable && migrated && connection_established?
  end

  # Finishes {#connect} after `ApplicationRecord.establish_connection` has succeeded by {#migrate migrating database}
  # and setting {#workspace}.
  #
  # @return [void]
  def after_establish_connection(opts={})
    begin
      # Migrate the database, if needed
      migrate(opts)
    rescue ::Exception => exception
      self.error = exception
      elog('DB.connect threw an exception', error: exception)

      # remove connection to prevent issues when re-establishing connection
      ApplicationRecord.remove_connection
    else
      # Flag that migration has completed
      self.migrated = true
    end
  end

  #
  # Connects this instance to a database
  #
  def connect(opts={})
    return false if not @usable

    nopts = opts.dup
    if (nopts['port'])
      nopts['port'] = nopts['port'].to_i
    end

    # Prefer the config file's pool setting
    nopts['pool'] ||= 75

    # Prefer the config file's wait_timeout setting too
    nopts['wait_timeout'] ||= 300

    begin
      # Check ApplicationRecord was already connected by Rails::Application.initialize! or some other API.
      unless connection_established?
        create_db(nopts)

        # Configure the database adapter
        ApplicationRecord.establish_connection(nopts)
      end
    rescue ::Exception => e
      self.error = e
      elog('DB.connect threw an exception', error: e)
      return false
    ensure
      after_establish_connection(nopts)
    end

    true
  end


  #
  # Attempt to create the database
  #
  # If the database already exists this will fail and we will continue on our
  # merry way, connecting anyway.  If it doesn't, we try to create it.  If
  # that fails, then it wasn't meant to be and the connect will raise a
  # useful exception so the user won't be in the dark; no need to raise
  # anything at all here.
  #
  def create_db(opts)
    begin
      case opts["adapter"]
      when 'postgresql'
        # Try to force a connection to be made to the database, if it succeeds
        # then we know we don't need to create it :)
        ApplicationRecord.establish_connection(opts)
        # Do the checkout, checkin dance here to make sure this thread doesn't
        # hold on to a connection we don't need
        conn = ApplicationRecord.connection_pool.checkout
        ApplicationRecord.connection_pool.checkin(conn)
      end
    rescue ::Exception => e
      errstr = e.to_s
      if errstr =~ /does not exist/i or errstr =~ /Unknown database/
        ilog("Database doesn't exist \"#{opts['database']}\", attempting to create it.")
        ApplicationRecord.establish_connection(
            opts.merge(
                'database' => 'postgres',
                'schema_search_path' => 'public'
            )
        )

        ApplicationRecord.connection.create_database(opts['database'])
      else
        ilog("Trying to continue despite failed database creation: #{e}")
      end
    end
    ApplicationRecord.remove_connection
  end

  # Checks if the spec passed to `ApplicationRecord.establish_connection` can connect to the database.
  #
  # @return [true] if an active connection can be made to the database using the current config.
  # @return [false] if an active connection cannot be made to the database.
  def connection_established?
    begin
      # use with_connection so the connection doesn't stay pinned to the thread.
      ApplicationRecord.connection_pool.with_connection do
        # There's a bug in Rails 7.1 where ApplicationRecord.connection.active? returns false even though we can get a connection
        # calling `verify!` instead will ensure we are connected even if `active?` incorrectly returns false
        ApplicationRecord.connection.verify!
      end
    rescue ActiveRecord::ConnectionNotEstablished, PG::ConnectionBad => error
      false
    end
  end

  #
  # Disconnects a database session
  #
  def disconnect
    begin
      ApplicationRecord.remove_connection
      self.migrated = nil
      self.modules_cached = false
    rescue ::Exception => e
      self.error = e
      elog('DB.disconnect threw an exception:', error: e)
    end
  end
end
