module Metasploit
	module Framework
		module Module
			module PathSet
				# Set of database module paths.
				class Database < Metasploit::Framework::Module::PathSet::Base
					# Error raised by {Metasploit::Framework::Module::PathSet::Database}.
					class Error < Metasploit::Framework::Module::PathSet::Error

					end

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
							Mdm::Module::Path.transaction do
								unless path.valid?(:add)
									raise ActiveRecord::RecordInvalid.new(path)
								end

								name_collision = nil
								real_path_collision = Mdm::Module::Path.where(
										:real_path => path.real_path
								).first

								# Don't query for gem IS NULL and path IS NULL as it will return
								# all unnamed paths which only need to be checked for real_path
								# collisions, which is already handled above.
								if path.named?
									name_collision = Mdm::Module::Path.where(
											:gem => path.gem,
											:name => path.name
									).first
								end

								if name_collision and real_path_collision
									if name_collision != real_path_collision
										raise Metasploit::Framework::Module::PathSet::Database::Error,
													"Collision against two pre-existing " \
													"Mdm::Module::Paths: (1) #{name_collision.id} on " \
													"gem (#{name_collision.gem}) and name " \
													"(#{name_collision.name}) and (2) " \
													"#{real_path_collision.id} on real_path " \
													"(#{real_path_collision.real_path})."
									end

									# collision is already path
									added = name_collision
								elsif name_collision
									# Update (real_path) as newer path as a named path is
									# preferred.
									name_collision.real_path = path.real_path
									name_collision.save!

									added = name_collision
								elsif real_path_collision
									# Update (gem, name) as its better to have a named path
									# than an unnamed path.
									if path.named?
										real_path_collision.gem = path.gem
										real_path_collision.name = path.name
										real_path_collision.save!
									end

									added = real_path_collision
  							# New (gem, name) and real_path
								else
									path.save!

									added = path
								end
							end
						end

						added
					end
				end
			end
		end
	end
end