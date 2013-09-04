# @abstract Implement {#add} following its abstract guidelines.
#
# A set of {Metasploit::Framework::Module::Path
# Metasploit::Framework::Module::Paths} or Mdm::Module::Paths (depending
# on if the database is active.)
class Metasploit::Framework::Module::PathSet::Base < Metasploit::Model::Base
	#
	# Attributes
	#

	# @!attribute [rw] cache
	#   The cache that contains this path set.
	#
	#   @return [Metasploit::Framework::Module::Cache]
	attr_accessor :cache

	#
	# Validations
	#

	validates :cache,
						:presence => true

	#
	# Methods
	#

	# @abstract Instantiate a subclass specific path class and validate it before
	#   calling {#add_path} with the path instance.  If the path instance is
	#   invalid, raise a validation error.
	#
	# Adds path to this set.
	#
	# @param path [String] path with modules
	# @param options [Hash{Symbol => String}]
	# @option options [String] :gem The name of the gem that is adding this
	#   module path to metasploit-framework.  For paths normally added by
	#   metasploit-framework itself, this would be `'metasploit-framework'`,
	#   while for Metasploit Pro this would be `'metasploit-pro'`.  The
	#   name used for `gem` does not have to be a gem on rubygems, it just
	#   functions as a namespace for :name so that projects using
	#   metasploit-framework do not need to worry about collisions on
	#   :name which could disrupt the cache behavior.
	# @option options [String] :name The name scoped to :gem of path.
	# @raise [NotImplementedError]
	def add(path, options={})
		raise NotImplementedError,
					"#{self.class.name}##{__method__} is not implemented"
	end

	# All paths.
	#
	# @return [Array<Metasploit::Model::Module::Path>] paths
	def all
		raise NotImplementedErrror,
					"#{self.class.name}##{__method__} is not implemented"
	end

	# Verifies that this set is a superset of the given paths.
	#
	# @param module_paths [Enumerable<Metasploit::Model::Module::Path>] module
	#   paths that need to be checked if they are in this path set.
	# @return [void]
	# @raise [Metasploit::Framework::Module::PathSet::SupersetError] if there are
	#   module paths in `module_paths` that are not in this path set.
	def superset!(module_paths)
		raise NotImplementedError,
					"#{self.class.name}##{__method__} is not implemented"
	end

	protected

	# Adds path object to this set.
	#
	# @param path [Metasploit::Model::Module::Path] instance of path class that
	#   has Metasploit::Model::Module::Path included.
	# @return [Metasploit::Model::Module::Path] path that was added or updated in
	#   this set.  It may not be the same as `path` if `path` has a name
	#   or real_path collision, in which case the returned path will be the
	#   collision with updated attributes from `path`.
	def add_path(path)
		name_collision = path.name_collision
		real_path_collision = path.real_path_collision

		if name_collision and real_path_collision
			if name_collision != real_path_collision
				raise Metasploit::Framework::Module::PathSet::Error,
							"Collision against two pre-existing " \
							"#{path.class.name.pluralize}: (1) on gem " \
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
end
