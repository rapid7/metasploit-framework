# frozen_string_literal: true
require 'fileutils'
require 'thread'

module YARD
  module Server
    # This exception is raised when {LibraryVersion#prepare!} fails, or discovers
    # that the library is not "prepared" to be served by
    class LibraryNotPreparedError < RuntimeError; end

    # A library version encapsulates a library's documentation at a specific version.
    # Although the version is optional, this allows for creating multiple documentation
    # points for a specific library, each representing a unique version. The term
    # "library" used in other parts of the YARD::Server documentation refers to
    # objects of this class unless otherwise noted.
    #
    # A library points to a location where a {#yardoc_file} is located so that
    # its documentation may be loaded and served. Optionally, a {#source_path} is
    # given to point to a location where any extra files (and {YARD::CLI::Yardoc .yardopts})
    # should be loaded from. Both of these methods may not be known immediately,
    # since the yardoc file may not be built until later. Resolving the yardoc
    # file and source path are dependent on the specific library "source type" used.
    # Source types (known as "library source") are discussed in detail below.
    #
    # == Using with Adapters
    # A list of libraries need to be passed into adapters upon creation. In
    # most cases, you will never do this manually, but if you use a {RackMiddleware},
    # you will need to pass in this list yourself. To build this list of libraries,
    # you should create a hash of library names mapped to an *Array* of LibraryVersion
    # objects. For example:
    #
    #   {'mylib' => [LibraryVersion.new('mylib', '1.0', ...),
    #                LibraryVersion.new('mylib', '2.0', ...)]}
    #
    # Note that you can also use {Adapter#add_library} for convenience.
    #
    # The "array" part is required, even for just one library version.
    #
    # == Library Sources
    # The {#source} method represents the library source type, ie. where the
    # library "comes from". It might come from "disk", or it might come from a
    # "gem" (technically the disk, but a separate type nonetheless). In these
    # two cases, the yardoc file sits somewhere on your filesystem, though
    # it may also be built dynamically if it does not yet exist. This behaviour
    # is controlled through the {#prepare!} method, which prepares the yardoc file
    # given a specific library source. We will see how this works in detail in
    # the following section.
    #
    # == Implementing a Custom Library Source
    # YARD can be extended to support custom library sources in order to
    # build or retrieve a yardoc file at runtime from many different locations.
    #
    # To implement this behaviour, 3 methods can be added to the +LibraryVersion+
    # class, +#load_yardoc_from_SOURCE+, +#yardoc_file_for_SOURCE+, and
    # +#source_path_for_SOURCE+. In all cases, "SOURCE" represents the source
    # type used in {#source} when creating the library object. The
    # +#yardoc_file_for_SOURCE+ and +#source_path_for_SOURCE+ methods are called upon
    # creation and should return the location where the source code for the library
    # lives. The load method is called from {#prepare!} if there is no yardoc file
    # and should set {#yardoc_file}. Below is a full example for
    # implementing a custom library source, +:http+, which reads packaged .yardoc
    # databases from zipped archives off of an HTTP server.
    #
    # Note that only +#load_yardoc_from_SOURCE+ is required. The other two
    # methods are optional and can be set manually (via {#source_path=} and
    # {#yardoc_file=}) on the object at any time.
    #
    # @example Implementing a Custom Library Source
    #   # Adds the source type "http" for .yardoc files zipped on HTTP servers
    #   class LibraryVersion
    #     def load_yardoc_from_http
    #       Thread.new do
    #         # zip/unzip method implementations are not shown
    #         download_zip_file("http://mysite.com/yardocs/#{self}.zip")
    #         unzip_file_to("/path/to/yardocs/#{self}")
    #       end
    #
    #       # tell the server it's not ready yet (but it might be next time)
    #       raise LibraryNotPreparedError
    #     end
    #
    #     def yardoc_file_for_http
    #       "/path/to/yardocs/#{self}/.yardoc"
    #     end
    #
    #     def source_path_for_http
    #       File.dirname(yardoc_file)
    #     end
    #   end
    #
    #   # Creating a library of this source type:
    #   LibraryVersion.new('name', '1.0', nil, :http)
    #
    class LibraryVersion
      # @return [String] the name of the library
      attr_accessor :name

      # @return [String] the version of the specific library
      attr_accessor :version

      # @return [String] the location of the yardoc file used to load the object
      #   information from.
      # @return [nil] if no yardoc file exists yet. In this case, {#prepare!} will
      #   be called on this library to build the yardoc file.
      # @note To implement a custom yardoc file getter, implement
      def yardoc_file
        @yardoc_file ||= load_yardoc_file
      end
      attr_writer :yardoc_file

      # @return [Symbol] the source type representing where the yardoc should be
      #   loaded from. Defaults are +:disk+ and +:gem+, though custom sources
      #   may be implemented. This value is used to inform {#prepare!} about how
      #   to load the necessary data in order to display documentation for an object.
      # @see LibraryVersion LibraryVersion documentation for "Implementing a Custom Library Source"
      attr_accessor :source

      # @return [String] the location of the source code for a library. This
      #   value is filled by calling +#source_path_for_SOURCE+ on this class.
      # @return [nil] if there is no source code
      # @see LibraryVersion LibraryVersion documentation for "Implementing a Custom Library Source"
      def source_path
        @source_path ||= load_source_path
      end
      attr_writer :source_path

      # @param [String] name the name of the library
      # @param [String] version the specific (usually, but not always, numeric) library
      #   version
      # @param [String] yardoc the location of the yardoc file, or nil if it is
      #   generated later
      # @param [Symbol] source the location of the files used to build the yardoc.
      #   Builtin source types are +:disk+ or +:gem+.
      def initialize(name, version = nil, yardoc = nil, source = :disk)
        self.name = name
        self.yardoc_file = yardoc
        self.version = version
        self.source = source
      end

      # @param [Boolean] url_format if true, returns the string in a URI-compatible
      #   format (for appending to a URL). Otherwise, it is given in a more human
      #   readable format.
      # @return [String] the string representation of the library.
      def to_s(url_format = true)
        version ? "#{name}#{url_format ? '/' : '-'}#{version}" : name.to_s
      end

      # @return [Fixnum] used for Hash mapping.
      def hash; to_s.hash end

      # @return [Boolean] whether another LibraryVersion is equal to this one
      def eql?(other)
        other.is_a?(LibraryVersion) && other.name == name &&
          other.version == version && other.yardoc_file == yardoc_file
      end
      alias == eql?
      alias equal? eql?

      # @return [Boolean] whether the library has been completely processed
      #   and is ready to be served
      def ready?
        return false if yardoc_file.nil?
        serializer.complete?
      end

      # @note You should not directly override this method. Instead, implement
      #   +load_yardoc_from_SOURCENAME+ when implementing loading for a specific
      #   source type. See the {LibraryVersion} documentation for "Implementing
      #   a Custom Library Source"
      #
      # Prepares a library to be displayed by the server. This callback is
      # performed before each request on a library to ensure that it is loaded
      # and ready to be viewed. If any steps need to be performed prior to loading,
      # they are performed through this method (though they should be implemented
      # through the +load_yardoc_from_SOURCE+ method).
      #
      # @raise [LibraryNotPreparedError] if the library is not ready to be
      #   displayed. Usually when raising this error, you would simultaneously
      #   begin preparing the library for subsequent requests, although this
      #   is not necessary.
      def prepare!
        return if ready?
        meth = "load_yardoc_from_#{source}"
        send(meth) if respond_to?(meth, true)
      end

      # @return [Gem::Specification] a gemspec object for a given library. Used
      #   for :gem source types.
      # @return [nil] if there is no installed gem for the library
      def gemspec
        ver = version ? "= #{version}" : ">= 0"
        YARD::GemIndex.find_all_by_name(name, ver).last
      end

      protected

      @@chdir_mutex = Mutex.new

      # Called when a library of source type "disk" is to be prepared. In this
      # case, the {#yardoc_file} should already be set, but the library may not
      # be prepared. Run preparation if not done.
      #
      # @raise [LibraryNotPreparedError] if the yardoc file has not been
      #   prepared.
      def load_yardoc_from_disk
        return if ready?

        @@chdir_mutex.synchronize do
          Dir.chdir(source_path_for_disk) do
            Thread.new do
              CLI::Yardoc.run('--no-stats', '-n', '-b', yardoc_file)
            end
          end
        end

        raise LibraryNotPreparedError
      end

      # Called when a library of source type "gem" is to be prepared. In this
      # case, the {#yardoc_file} needs to point to the correct location for
      # the installed gem. The yardoc file is built if it has not been done.
      #
      # @raise [LibraryNotPreparedError] if the gem does not have an existing
      #   yardoc file.
      def load_yardoc_from_gem
        return if ready?
        ver = version ? "= #{version}" : ">= 0"

        @@chdir_mutex.synchronize do
          Thread.new do
            # Build gem docs on demand
            log.debug "Building gem docs for #{to_s(false)}"
            CLI::Gems.run(name, ver)
            log.debug "Done building gem docs for #{to_s(false)}"
          end
        end

        raise LibraryNotPreparedError
      end

      # @return [String] the source path for a disk source
      def source_path_for_disk
        File.dirname(yardoc_file) if yardoc_file
      end

      # @return [String] the source path for a gem source
      def source_path_for_gem
        gemspec.full_gem_path if gemspec
      end

      # @return [String] the yardoc file for a gem source
      def yardoc_file_for_gem
        require 'rubygems'
        ver = version ? "= #{version}" : ">= 0"
        Registry.yardoc_file_for_gem(name, ver)
      end

      private

      def load_source_path
        meth = "source_path_for_#{source}"
        send(meth) if respond_to?(meth, true)
      end

      def load_yardoc_file
        meth = "yardoc_file_for_#{source}"
        send(meth) if respond_to?(meth, true)
      end

      def serializer
        return if yardoc_file.nil?
        Serializers::YardocSerializer.new(yardoc_file)
      end
    end
  end
end
