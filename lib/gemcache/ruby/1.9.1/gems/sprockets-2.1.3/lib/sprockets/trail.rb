require 'sprockets/errors'
require 'pathname'

module Sprockets
  # `Trail` is an internal mixin whose public methods are exposed on
  # the `Environment` and `Index` classes.
  module Trail
    # Returns `Environment` root.
    #
    # All relative paths are expanded with root as its base. To be
    # useful set this to your applications root directory. (`Rails.root`)
    def root
      trail.root.dup
    end

    # Returns an `Array` of path `String`s.
    #
    # These paths will be used for asset logical path lookups.
    #
    # Note that a copy of the `Array` is returned so mutating will
    # have no affect on the environment. See `append_path`,
    # `prepend_path`, and `clear_paths`.
    def paths
      trail.paths.dup
    end

    # Prepend a `path` to the `paths` list.
    #
    # Paths at the end of the `Array` have the least priority.
    def prepend_path(path)
      expire_index!
      @trail.prepend_path(path)
    end

    # Append a `path` to the `paths` list.
    #
    # Paths at the beginning of the `Array` have a higher priority.
    def append_path(path)
      expire_index!
      @trail.append_path(path)
    end

    # Clear all paths and start fresh.
    #
    # There is no mechanism for reordering paths, so its best to
    # completely wipe the paths list and reappend them in the order
    # you want.
    def clear_paths
      expire_index!
      @trail.paths.dup.each { |path| @trail.remove_path(path) }
    end

    # Returns an `Array` of extensions.
    #
    # These extensions maybe omitted from logical path searches.
    #
    #     # => [".js", ".css", ".coffee", ".sass", ...]
    #
    def extensions
      trail.extensions.dup
    end

    # Finds the expanded real path for a given logical path by
    # searching the environment's paths.
    #
    #     resolve("application.js")
    #     # => "/path/to/app/javascripts/application.js.coffee"
    #
    # A `FileNotFound` exception is raised if the file does not exist.
    def resolve(logical_path, options = {})
      # If a block is given, preform an iterable search
      if block_given?
        args = attributes_for(logical_path).search_paths + [options]
        trail.find(*args) do |path|
          yield Pathname.new(path)
        end
      else
        resolve(logical_path, options) do |pathname|
          return pathname
        end
        raise FileNotFound, "couldn't find file '#{logical_path}'"
      end
    end

    protected
      def trail
        @trail
      end
  end
end
