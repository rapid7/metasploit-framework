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
end
