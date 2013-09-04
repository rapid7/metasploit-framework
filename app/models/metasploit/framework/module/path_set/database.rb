# Set of database module paths.
class Metasploit::Framework::Module::PathSet::Database < Metasploit::Framework::Module::PathSet::Base
	# Adds path to set in database.
	#
	# @param (see Metasploit::Framework::Module::PathSet::Base)
	# @option (see Metasploit::Framework::Module::PathSet::Base)
	# @return [Mdm::Module::Path]
	# @raise [ActiveRecord::RecordInvalid] if Mdm::Module::Path is invalid
	#   for `:add` context.
	def add(real_path, options={})
		path = Mdm::Module::Path.new(
				:gem => options[:gem],
				:name => options[:name],
				:real_path => real_path
		)
		added = nil

		Mdm::Module::Path.connection_pool.with_connection do
			# Start transaction before validating as validation may interact with the
			# database.
			Mdm::Module::Path.transaction do
				unless path.valid?(:add)
					raise ActiveRecord::RecordInvalid.new(path)
				end

				added = add_path(path)
			end
		end

		added
	end

	# @note Returns an `Array<Mdm::Module::Path>` instead of an
	#   `ActiveRecord::Relation` so there is no need to protect access to the
	#   `Mdm::Module::Path` with an
	#   `ActiveRecord::Base.connection_pool.with_connection` block.
	#
	# All paths.
	#
	# @return [Array<Mdm::Module::Path>]
	def all
		Mdm::Module::Path.connection_pool.with_connection do
			Mdm::Module::Path.all.to_a
		end
	end

	# Verifies that this set is a superset of the given paths.
	#
	# @param module_paths [Enumerable<Mdm::Module::Path>] module paths that need
	#   to be checked if they are in this path set.
	# @return (see Metasploit::Framework::Module::PathSet::Base#superset!)
	# @raise (see Metasploit::Framework::Module::PathSet::Base#superset!)
	def superset!(module_paths)
		Mdm::Module::Path.connection_pool.with_connection do
			excluded_module_paths = module_paths.select { |module_path|
				!module_path.persisted?
			}

			unless excluded_module_paths.empty?
				raise Metasploit::Framework::Module::PathSet::SupersetError.new(
									excluded_module_paths: excluded_module_paths,
									path_set: self
							)
			end
		end
	end
end
