require 'time'
require 'set'

module Sprockets
  # `Asset` is the base class for `BundledAsset` and `StaticAsset`.
  class Asset
    # Internal initializer to load `Asset` from serialized `Hash`.
    def self.from_hash(environment, hash)
      return unless hash.is_a?(Hash)

      klass = case hash['class']
        when 'BundledAsset'
          BundledAsset
        when 'ProcessedAsset'
          ProcessedAsset
        when 'StaticAsset'
          StaticAsset
        else
          nil
        end

      if klass
        asset = klass.allocate
        asset.init_with(environment, hash)
        asset
      end
    rescue UnserializeError
      nil
    end

    attr_reader :logical_path, :pathname
    attr_reader :content_type, :mtime, :length, :digest

    def initialize(environment, logical_path, pathname)
      @root         = environment.root
      @logical_path = logical_path.to_s
      @pathname     = Pathname.new(pathname)
      @content_type = environment.content_type_of(pathname)
      @mtime        = environment.stat(pathname).mtime
      @length       = environment.stat(pathname).size
      @digest       = environment.file_digest(pathname).hexdigest
    end

    # Initialize `Asset` from serialized `Hash`.
    def init_with(environment, coder)
      @root = environment.root

      @logical_path = coder['logical_path']
      @content_type = coder['content_type']
      @digest       = coder['digest']

      if pathname = coder['pathname']
        # Expand `$root` placeholder and wrapper string in a `Pathname`
        @pathname = Pathname.new(expand_root_path(pathname))
      end

      if mtime = coder['mtime']
        # Parse time string
        @mtime = Time.parse(mtime)
      end

      if length = coder['length']
        # Convert length to an `Integer`
        @length = Integer(length)
      end
    end

    # Copy serialized attributes to the coder object
    def encode_with(coder)
      coder['class']        = self.class.name.sub(/Sprockets::/, '')
      coder['logical_path'] = logical_path
      coder['pathname']     = relativize_root_path(pathname).to_s
      coder['content_type'] = content_type
      coder['mtime']        = mtime.iso8601
      coder['length']       = length
      coder['digest']       = digest
    end

    # Return logical path with digest spliced in.
    #
    #   "foo/bar-37b51d194a7513e45b56f6524f2d51f2.js"
    #
    def digest_path
      logical_path.sub(/\.(\w+)$/) { |ext| "-#{digest}#{ext}" }
    end

    # Return an `Array` of `Asset` files that are declared dependencies.
    def dependencies
      []
    end

    # Expand asset into an `Array` of parts.
    #
    # Appending all of an assets body parts together should give you
    # the asset's contents as a whole.
    #
    # This allows you to link to individual files for debugging
    # purposes.
    def to_a
      [self]
    end

    # `body` is aliased to source by default if it can't have any dependencies.
    def body
      source
    end

    # Return `String` of concatenated source.
    def to_s
      source
    end

    # Add enumerator to allow `Asset` instances to be used as Rack
    # compatible body objects.
    def each
      yield to_s
    end

    # Checks if Asset is fresh by comparing the actual mtime and
    # digest to the inmemory model.
    #
    # Used to test if cached models need to be rebuilt.
    def fresh?(environment)
      # Check current mtime and digest
      dependency_fresh?(environment, self)
    end

    # Checks if Asset is stale by comparing the actual mtime and
    # digest to the inmemory model.
    #
    # Subclass must override `fresh?` or `stale?`.
    def stale?(environment)
      !fresh?(environment)
    end

    # Save asset to disk.
    def write_to(filename, options = {})
      # Gzip contents if filename has '.gz'
      options[:compress] ||= File.extname(filename) == '.gz'

      File.open("#{filename}+", 'wb') do |f|
        if options[:compress]
          # Run contents through `Zlib`
          gz = Zlib::GzipWriter.new(f, Zlib::BEST_COMPRESSION)
          gz.write to_s
          gz.close
        else
          # Write out as is
          f.write to_s
          f.close
        end
      end

      # Atomic write
      FileUtils.mv("#{filename}+", filename)

      # Set mtime correctly
      File.utime(mtime, mtime, filename)

      nil
    ensure
      # Ensure tmp file gets cleaned up
      FileUtils.rm("#{filename}+") if File.exist?("#{filename}+")
    end

    # Pretty inspect
    def inspect
      "#<#{self.class}:0x#{object_id.to_s(16)} " +
        "pathname=#{pathname.to_s.inspect}, " +
        "mtime=#{mtime.inspect}, " +
        "digest=#{digest.inspect}" +
        ">"
    end

    def hash
      digest.hash
    end

    # Assets are equal if they share the same path, mtime and digest.
    def eql?(other)
      other.class == self.class &&
        other.logical_path == self.logical_path &&
        other.mtime.to_i == self.mtime.to_i &&
        other.digest == self.digest
    end
    alias_method :==, :eql?

    protected
      # Internal: String paths that are marked as dependencies after processing.
      #
      # Default to an empty `Array`.
      def dependency_paths
        @dependency_paths ||= []
      end

      # Internal: `ProccessedAsset`s that are required after processing.
      #
      # Default to an empty `Array`.
      def required_assets
        @required_assets ||= []
      end

      # Get pathname with its root stripped.
      def relative_pathname
        @relative_pathname ||= Pathname.new(relativize_root_path(pathname))
      end

      # Replace `$root` placeholder with actual environment root.
      def expand_root_path(path)
        path.to_s.sub(/^\$root/, @root)
      end

      # Replace actual environment root with `$root` placeholder.
      def relativize_root_path(path)
        path.to_s.sub(/^#{Regexp.escape(@root)}/, '$root')
      end

      # Check if dependency is fresh.
      #
      # `dep` is a `Hash` with `path`, `mtime` and `hexdigest` keys.
      #
      # A `Hash` is used rather than other `Asset` object because we
      # want to test non-asset files and directories.
      def dependency_fresh?(environment, dep)
        path, mtime, hexdigest = dep.pathname.to_s, dep.mtime, dep.digest

        stat = environment.stat(path)

        # If path no longer exists, its definitely stale.
        if stat.nil?
          return false
        end

        # Compare dependency mime to the actual mtime. If the
        # dependency mtime is newer than the actual mtime, the file
        # hasn't changed since we created this `Asset` instance.
        #
        # However, if the mtime is newer it doesn't mean the asset is
        # stale. Many deployment environments may recopy or recheckout
        # assets on each deploy. In this case the mtime would be the
        # time of deploy rather than modified time.
        if mtime >= stat.mtime
          return true
        end

        digest = environment.file_digest(path)

        # If the mtime is newer, do a full digest comparsion. Return
        # fresh if the digests match.
        if hexdigest == digest.hexdigest
          return true
        end

        # Otherwise, its stale.
        false
      end
  end
end
