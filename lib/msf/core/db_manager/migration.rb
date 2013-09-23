module Msf::DBManager::Migration
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
