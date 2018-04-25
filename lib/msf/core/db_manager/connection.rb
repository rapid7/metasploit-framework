module Msf::DBManager::Connection
  # Returns true if we are ready to load/store data
  def active
    # usable and migrated a just Boolean attributes, so check those first because they don't actually contact the
    # database.
    usable && migrated && connection_established?
  end

  # Finishes {#connect} after `ActiveRecord::Base.establish_connection` has succeeded by {#migrate migrating database}
  # and setting {#workspace}.
  #
  # @return [void]
  def after_establish_connection
    self.migrated = false

    begin
      # Migrate the database, if needed
      migrate
    rescue ::Exception => exception
      self.error = exception
      elog("DB.connect threw an exception: #{exception}")
      dlog("Call stack: #{exception.backtrace.join("\n")}", LEV_1)
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
      self.migrated = false

      # Check ActiveRecord::Base was already connected by Rails::Application.initialize! or some other API.
      unless connection_established?
        create_db(nopts)

        # Configure the database adapter
        ActiveRecord::Base.establish_connection(nopts)
      end
    rescue ::Exception => e
      self.error = e
      elog("DB.connect threw an exception: #{e}")
      dlog("Call stack: #{$@.join"\n"}", LEV_1)
      return false
    ensure
      after_establish_connection
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
        ActiveRecord::Base.establish_connection(opts)
        # Do the checkout, checkin dance here to make sure this thread doesn't
        # hold on to a connection we don't need
        conn = ActiveRecord::Base.connection_pool.checkout
        ActiveRecord::Base.connection_pool.checkin(conn)
      end
    rescue ::Exception => e
      errstr = e.to_s
      if errstr =~ /does not exist/i or errstr =~ /Unknown database/
        ilog("Database doesn't exist \"#{opts['database']}\", attempting to create it.")
        ActiveRecord::Base.establish_connection(
            opts.merge(
                'database' => 'postgres',
                'schema_search_path' => 'public'
            )
        )

        ActiveRecord::Base.connection.create_database(opts['database'])
      else
        ilog("Trying to continue despite failed database creation: #{e}")
      end
    end
    ActiveRecord::Base.remove_connection
  end

  # Checks if the spec passed to `ActiveRecord::Base.establish_connection` can connect to the database.
  #
  # @return [true] if an active connection can be made to the database using the current config.
  # @return [false] if an active connection cannot be made to the database.
  def connection_established?
    begin
      # use with_connection so the connection doesn't stay pinned to the thread.
      ActiveRecord::Base.connection_pool.with_connection {
        ActiveRecord::Base.connection.active?
      }
    rescue ActiveRecord::ConnectionNotEstablished, PG::ConnectionBad => error
      false
    end
  end

  #
  # Disconnects a database session
  #
  def disconnect
    begin
      ActiveRecord::Base.remove_connection
      self.migrated = false
      self.modules_cached = false
    rescue ::Exception => e
      self.error = e
      elog("DB.disconnect threw an exception: #{e}")
    end
  end
end
