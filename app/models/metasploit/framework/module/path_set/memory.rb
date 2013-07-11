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

						name_collision = nil
						real_path_collision = path_by_real_path[path.real_path]

						# Don't check path_by_name_by_gem if gem and name are nil since
						# path_by_name_by_gem doesn't support nils.
						if path.named?
							path_by_name = path_by_name_by_gem[path.gem]
							name_collision = path_by_name[path.name]
						end

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
							# remove entry for old path
							path_by_real_path.delete(name_collision.real_path)

							# Update (real_path) as newer path as a named path is preferred.
							name_collision.real_path = path.real_path
							# store new real_path to preserve uniqueness checks and allow for
							# updates using new real_path
							path_by_real_path[name_collision.real_path] = name_collision

							name_collision.update_module_ancestor_real_paths

							added = name_collision
						elsif real_path_collision
							# prevent a named real_path_collision being replaced by an unnamed
							# new path as it is better for a real_path to have a (gem, name).
							if path.named?
								# remove entry for old name
								if real_path_collision.named?
									path_by_name = path_by_name_by_gem[real_path_collision.gem]
									path_by_name.delete(real_path_collision.name)
								end

								real_path_collision.gem = path.gem
								real_path_collision.name = path.name

								# store new (gem, name) to preserve uniqueness checks and allow
								# or updates using new (gem, name).
								path_by_name = path_by_name_by_gem[real_path_collision.gem]
								path_by_name[real_path_collision.name] = real_path_collision
							end

							added = real_path_collision
						# New (gem, name) and real_path
						else
							if path.named?
								path_by_name = path_by_name_by_gem[path.gem]
								path_by_name[path.name] = path
							end

							path_by_real_path[path.real_path] = path

							added = path
						end

						added.reset_changes

						added
					end

					private

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
				end
			end
		end
	end
end