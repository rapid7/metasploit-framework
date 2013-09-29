module Msf::DBManager::Migration
  extend ActiveSupport::Concern

  included do
    include ActiveModel::Validations

    #
    # Validations
    #

    validate :no_migration_error
  end

  #
  # Attributes
  #

  # @!attribute [r] migration_error
  #   Error raised by {#migrate}
  #
  #   @return [nil] if no error
  #   @return [StandardError] if a migration could not be run.
  attr_reader :migration_error

  #
  # Methods
  #

  # Migrate database to latest schema version.
  #
  # @param options [Hash{Symbol => Boolean}]
  # @option options [Boolean] :verbose (false) (see ActiveRecord::Migration.verbose)
  # @return [true] if migrations ran without error or already migrated
  # @return [false] otherwise
  #
  # @see ActiveRecord::Migrator.migrate
  def migrate(options={})
    options.assert_valid_keys(:verbose)
    verbose = options[:verbose] || false

    unless migrated?
      synchronize do
        unless migrated?
          ActiveRecord::Migration.verbose = verbose

          # Can't use #with_connection since it depends on migrated? being true, so have to be lower level call
          ActiveRecord::Base.connection_pool.with_connection do
            begin
              ActiveRecord::Migrator.migrate(
                  ActiveRecord::Migrator.migrations_paths
              )
            rescue StandardError => error
              @migration_error = error
              # ActiveRecord::Migrator#migrate rescues all errors and re-raises them
              # as StandardError
              elog("#{self.class}##{__method__} threw an exception: #{error}")
              dlog("Call stack:\n#{error.backtrace.join "\n"}")
            else
              # Since the connections that existed before the migrations ran could
              # have outdated column information, reset column information for all
              # ActiveRecord::Base descendents to prevent missing method errors for
              # column methods for columns created in migrations after the column
              # information was cached.
              reset_column_information

              @migrated = true
            end
          end
        end
      end
    end

    @migrated
  end

  # Whether migrations have run
  #
  # @return [true] if {#migrate} ran successfully on last {#connect}.
  # @return [false] otherwise.
  def migrated?
    # doesn't need to be synchronized since reads of an instance variable are thread-safe
    # ensure its Boolean even when undefined
    !!@migrated
  end

  private

  # Validates there was no {#migration_error} in {#migrate}.  If there was a {#migration_error}, then it becomes a
  # validation error on :migration.
  #
  # @return [void]
  def no_migration_error
    if migration_error
      errors[:migration] << migration_error.to_s
    end
  end

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
