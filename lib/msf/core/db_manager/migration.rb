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
  # @param verbose [Boolean] see ActiveRecord::Migration.verbose
  # @return [Array<ActiveRecord::MigrationProxy] List of migrations that
  #   ran.
  #
  # @see ActiveRecord::Migrator.migrate
  def migrate(verbose=false)
    ran = []
    ActiveRecord::Migration.verbose = verbose

    ActiveRecord::Base.connection_pool.with_connection do
      begin
        ran = ActiveRecord::Migrator.migrate(
            ActiveRecord::Migrator.migrations_paths
        )
          # ActiveRecord::Migrator#migrate rescues all errors and re-raises them
          # as StandardError
      rescue StandardError => error
        self.error = error
        elog("DB.migrate threw an exception: #{error}")
        dlog("Call stack:\n#{error.backtrace.join "\n"}")
      end
    end

    # Since the connections that existed before the migrations ran could
    # have outdated column information, reset column information for all
    # ActiveRecord::Base descendents to prevent missing method errors for
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

  # Resets the column information for all descendants of ActiveRecord::Base
  # since some of the migrations may have cached column information that
  # has been updated by later migrations.
  #
  # @return [void]
  def reset_column_information
    ActiveRecord::Base.descendants.each do |descendant|
      descendant.reset_column_information
    end
  end
end
