module Msf
	class DBManager
		module Migration
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

				return ran
			end

			# Flag to indicate database migration has completed
			#
			# @return [Boolean]
			attr_accessor :migrated
		end
	end
end