module Metasploit
	module Framework
		module Module
			module PathSet
				class Memory < Metasploit::Framework::Module::PathSet::Base
					# Error raised by {Metasploit::Framework::Module::PathSet::Memory}
					class Error < Metasploit::Framework::Module::PathSet::Error
					end

					# Adds path to this set.
					#
					# @param (see Metasploit::Framework::Module::PathSet::Base)
					# @option (see Metasploit::Framework::Module::PathSet::Base)
					# @return [Metasploit::Framework::Module::Path]
					def add(real_path, options={})
						path = Metasploit::Framework::Module::Path.new(
								:gem => options[:gem],
								:name => options[:name],
								:real_path => real_path
						)

						unless path.valid?
							raise Metasploit::Framework::ModelInvalid.new(path)
						end

						path.path_set = self

						name_collision = path.name_collision
						real_path_collision = path.real_path_collision

						if name_collision and real_path_collision
							if name_collision != real_path_collision
								raise Metasploit::Framework::Module::PathSet::Memory::Error,
											"Collision against two pre-existing " \
											"Metasploit::Framework::Module::Paths: (1) on gem " \
											"(#{name_collision.gem}) and name " \
											"(#{name_collision.name}) and (2) on real_path " \
											"(#{real_path_collision.real_path})."
							end

							# collision is already path
							added = name_collision
						elsif name_collision
							# Update (real_path) as newer path is preferred.
							name_collision.real_path = path.real_path
							name_collision.save!

							added = name_collision
						elsif real_path_collision
							# prevent a named real_path_collision being replaced by an unnamed
							# new path as it is better for a real_path to have a (gem, name).
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

						added
					end

					# Maps (gem, name) tuples to their
					# {Metasploit::Framework::Module::Path paths}.
					# {Metasploit::Framework::Module::Path Paths} without a
					# {Metasploit::Framework::Module::Path#gem gem} are only stored in
					# {#paths_by_real_path}.
					#
					# @return [Hash{String => Metasploit::Framework::Module::Path}]
					def path_by_name_by_gem
						@path_by_name_by_gem ||= Hash.new { |path_by_name_by_gem, gem|
							path_by_name = {}
							path_by_name_by_gem[gem] = path_by_name
						}
					end

					# Maps real paths to their {Metasploit::Framework::Module::Path
					# paths}.  Used to prevent real path collisions between
					# {Metasploit::Framework::Module::Path paths} with and without
					# {Metasploit::Framework::Module::Path#gem}.
					# {Metasploit::Framework::Module::Path} with a
					# {Metasploit::Framework::Module::Path#gem} is favored over a
					# {Metasploit::Framework::Module:Path} without a
					# {Metasploit::Framework::Module::Path#gem}.
					#
					# @return [Hash{String => Measploit::Framework::Module::Path}]
					def path_by_real_path
						@path_by_real_path ||= {}
					end
				end
			end
		end
	end
end