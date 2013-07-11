module Metasploit
	module Framework
		module Module
			# In-memory equivalent of `Mdm::Module::Path`
			class Path
				include ActiveModel::Dirty
				include Metasploit::Model::Module::Path

				#
				# Attributes Methods - used to track changed attributes
				#

				define_attribute_method :gem
				define_attribute_method :name
				define_attribute_method :real_path

				#
				# Attributes
				#

				# @!attribute [rw] gem
				#   The name of the gem that is adding this module path to
				#   metasploit-framework.  For paths normally added by
				#   metasploit-framework itself, this would be `'metasploit-framework'`,
				#   while for Metasploit Pro this would be `'metasploit-pro'`.  The name
				#   used for `gem` does not have to be a gem on rubygems, it just
				#   functions as a namespace for {#name} so that projects using
				#   metasploit-framework do not need to worry about collisions on
				#   {#name} which could disrupt the cache behavior.
				#
				#   @return [String]
				attr_reader :gem

				# @!attribute [rw] name
				#   The name of the module path scoped to {#gem}.  {#gem} and {#name}
				#   uniquely identify this path so that if {#real_path} changes, the
				#   entire cache does not need to be invalidated because the change in
				#   {#real_path} will still be tied to the same ({#gem}, {#name}) tuple.
				#
				#   @return [String]
				attr_reader :name

				# @!attribute [rw] path_set
				#   The {Metasploit::Framework::Module::PathSet} to which this path
				#   belongs.  The path set is used to calculate {#name_collision} and
				#   {#real_path_collision}.  The path_set is also updated when this
				#   path is {#save! saved}.
				attr_reader :path_set

				# @!attribute [rw] real_path
				#   @note Non-real paths will be converted to real paths in a before
				#   validation callback, so take care to either pass real paths or pay
				#   attention when setting {#real_path} and then changing directories
				#   before validating.
				#
				#   The real (absolute) path to module path.
				#
				#   @return [String]
				attr_reader :real_path

				#
				# Methods
				#

				# Updates {#gem} value and marks {#gem} as changed if `gem` differs from
				# {#gem}.
				#
				# @param gem [String, nil] (see #gem)
				# @return [String, nil] `gem`
				def gem=(gem)
					unless gem == @gem
						gem_will_change!
					end

					@gem = gem
				end

				# @param attributes [Hash{Symbol => String}]
				# @option attributes [String, nil] :gem (see #gem)
				# @option attributes [String, nil] :name (see #name)
				# @option attributes [String] :real_path (see #real_path)
				def initialize(attributes={})
					attributes.each do |attribute, value|
						public_send("#{attribute}=", value)
					end
				end

				# The modules ancestors that use this as a
				# {Metasploit::Framework::Module::Ancestor#parent_path}.
				#
				# @return [Array<Metasploit::Framework::Module::Ancestor>]
				def module_ancestors
					@module_ancestors ||= []
				end

				# Updates {#name} value and marks {#name} as changed if `name` differs
				# from {#name}.
				#
				# @param name [String, nil] (see #name)
				# @return [String, nil] `name`
				def name=(name)
					unless name == @name
						name_will_change!
					end

					@name = name
				end

				# Sets {#path_set}.
				#
				# @param path_set [Metasploit::Framework::Module::PathSet::Memory] the
				#   path_set to which this path belongs.
				# @return [Metasploit::Framework::Module::PathSet::Memory] `path_set`
				# @raise [Metasploit::Framework::Module::Path::Error]
				def path_set=(path_set)
					unless self.path_set.nil? || self.path_set == path_set
						raise Metasploit::Framework::Module::Path::Error,
									'already associated with another Metasploit::Framework::Module::PathSet::Memory'
					end

					@path_set = path_set
				end

				# Updates {#real_path} value and marks {#real_path} as changed if
				# `real_path` differs from {#real_path}.
				#
				# @param real_path [String, nil] (see #real_path)
				# @return [String, nil] `real_path`
				def real_path=(real_path)
					unless real_path == @real_path
						real_path_will_change!
					end

					@real_path = real_path
				end

				# Resets #changes and stores old changes in #previous_changes.  Call in
				# place of `save` after any changed? checks are performed.
				#
				# @return [void]
				def reset_changes
					@previously_changed = changes
					@changed_attributes.clear
				end

				# If {#real_path} changes, then update the
				# {Metasploit::Framework::Module::Ancestor#real_path} for
				# {#module_ancestors}.
				#
				# @return [void]
				def update_module_ancestor_real_paths
					if real_path_changed?
						module_ancestors.each do |module_ancestor|
							# @todo update Metasploit::Framework::AncestorSet instance
							module_ancestor.real_path = module_ancestor.derived_real_path
						end
					end
				end
			end
		end
	end
end