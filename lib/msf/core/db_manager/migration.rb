# -*- coding: binary -*-
module Msf::DBManager::Migration
  # Loads Metasploit Data Models and adds its migrations to migrations paths.
  #
  # @return [void]
  def add_rails_engine_migration_paths
    unless defined? ActiveRecord
      fail "Bundle installed '--without #{Bundler.settings.without.join(' ')}'.  To clear the without option do " \
           "`bundle install --without ''` (the --without flag with an empty string) or `rm -rf .bundle` to remove " \
           "the .bundle/config manually and then `bundle install`"
    end

    ::Rails::Engine.subclasses.map(&:instance).each.each do |engine|
      migrations_paths = engine.paths['db/migrate'].existent_directories

      migrations_paths.each do |migrations_path|
        # Since ActiveRecord::Migrator.migrations_paths can persist between
        # instances of Msf::DBManager, such as in specs,
        # migrations_path may already be part of
        # migrations_paths, in which case it should not be added or multiple
        # migrations with the same version number errors will occur.
        unless ActiveRecord::Migrator.migrations_paths.include? migrations_path
          ActiveRecord::Migrator.migrations_paths << migrations_path
        end
      end
    end
  end

  # Migrate database to latest schema version.
  #
  # @param config [Hash] see ActiveRecord::Base.establish_connection
  # @param verbose [Boolean] see ActiveRecord::Migration.verbose
  # @return [Array<ActiveRecord::MigrationProxy] List of migrations that
  #   ran.
  #
  # @see ActiveRecord::MigrationContext.migrate
  def migrate(config=nil, verbose=false)
    ran = []
    # Rails 5 changes ActiveRecord parents means to migrate outside
    # the `rake` task framework has to dig a little lower into ActiveRecord
    # to set up the DB connection capable of interacting with migration.
    previouslyConnected = ActiveRecord::Base.connected?
    unless previouslyConnected
      ApplicationRecord.remove_connection
      ActiveRecord::Base.establish_connection(config)
    end
    ActiveRecord::Migration.verbose = verbose
    ActiveRecord::Base.connection_pool.with_connection do
      begin
        # When framework reached Rails 6 the path set here may be better suited a simple Array[]
        context = ActiveRecord::MigrationContext.new(ActiveRecord::Migrator.migrations_paths)
        if context.needs_migration?
          ran = context.migrate
        end
          # ActiveRecord::Migrator#migrate rescues all errors and re-raises them
          # as StandardError
      rescue StandardError => error
        self.error = error
        elog('DB.migrate threw an exception', error: error)
      end
    end

    unless previouslyConnected
      ActiveRecord::Base.remove_connection
      ApplicationRecord.establish_connection(config)
    end
    # Since the connections that existed before the migrations ran could
    # have outdated column information, reset column information for all
    # ApplicationRecord descendents to prevent missing method errors for
    # column methods for columns created in migrations after the column
    # information was cached.
    reset_column_information

    return ran
  end

  # Flag to indicate database migration has completed
  #
  # @return [Boolean]
  attr_accessor :migrated

  private

  # Resets the column information for all descendants of ApplicationRecord
  # since some of the migrations may have cached column information that
  # has been updated by later migrations.
  #
  # @return [void]
  def reset_column_information
    ApplicationRecord.descendants.each do |descendant|
      descendant.reset_column_information
    end
  end
end
