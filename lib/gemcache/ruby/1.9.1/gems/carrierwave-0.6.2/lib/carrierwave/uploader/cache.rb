# encoding: utf-8

module CarrierWave

  class FormNotMultipart < UploadError
    def message
      "You tried to assign a String or a Pathname to an uploader, for security reasons, this is not allowed.\n\n If this is a file upload, please check that your upload form is multipart encoded."
    end
  end

  ##
  # Generates a unique cache id for use in the caching system
  #
  # === Returns
  #
  # [String] a cache id in the format YYYYMMDD-HHMM-PID-RND
  #
  def self.generate_cache_id
    Time.now.strftime('%Y%m%d-%H%M') + '-' + Process.pid.to_s + '-' + ("%04d" % rand(9999))
  end

  module Uploader
    module Cache
      extend ActiveSupport::Concern

      include CarrierWave::Uploader::Callbacks
      include CarrierWave::Uploader::Configuration

      module ClassMethods

        ##
        # Removes cached files which are older than one day. You could call this method
        # from a rake task to clean out old cached files.
        #
        # You can call this method directly on the module like this:
        #
        #   CarrierWave.clean_cached_files!
        #
        # === Note
        #
        # This only works as long as you haven't done anything funky with your cache_dir.
        # It's recommended that you keep cache files in one place only.
        #
        def clean_cached_files!(seconds=60*60*24)
          Dir.glob(File.expand_path(File.join(cache_dir, '*'), CarrierWave.root)).each do |dir|
            time = dir.scan(/(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})/).first.map { |t| t.to_i }
            time = Time.utc(*time)
            if time < (Time.now.utc - seconds)
              FileUtils.rm_rf(dir)
            end
          end
        end
      end

      ##
      # Returns true if the uploader has been cached
      #
      # === Returns
      #
      # [Bool] whether the current file is cached
      #
      def cached?
        @cache_id
      end

      ##
      # Caches the remotely stored file
      #
      # This is useful when about to process images. Most processing solutions
      # require the file to be stored on the local filesystem.
      #
      def cache_stored_file!
        sanitized = SanitizedFile.new :tempfile => StringIO.new(file.read),
          :filename => File.basename(path), :content_type => file.content_type

        cache! sanitized
      end

      ##
      # Returns a String which uniquely identifies the currently cached file for later retrieval
      #
      # === Returns
      #
      # [String] a cache name, in the format YYYYMMDD-HHMM-PID-RND/filename.txt
      #
      def cache_name
        File.join(cache_id, full_original_filename) if cache_id and original_filename
      end

      ##
      # Caches the given file. Calls process! to trigger any process callbacks.
      #
      # By default, cache!() uses copy_to(), which operates by copying the file
      # to the cache, then deleting the original file.  If move_to_cache() is
      # overriden to return true, then cache!() uses move_to(), which simply
      # moves the file to the cache.  Useful for large files.
      #
      # === Parameters
      #
      # [new_file (File, IOString, Tempfile)] any kind of file object
      #
      # === Raises
      #
      # [CarrierWave::FormNotMultipart] if the assigned parameter is a string
      #
      def cache!(new_file)
        new_file = CarrierWave::SanitizedFile.new(new_file)

        unless new_file.empty?
          raise CarrierWave::FormNotMultipart if new_file.is_path? && ensure_multipart_form

          with_callbacks(:cache, new_file) do
            self.cache_id = CarrierWave.generate_cache_id unless cache_id

            @filename = new_file.filename
            self.original_filename = new_file.filename

            if move_to_cache
              @file = new_file.move_to(cache_path, permissions)
            else
              @file = new_file.copy_to(cache_path, permissions)
            end
          end
        end
      end

      ##
      # Retrieves the file with the given cache_name from the cache.
      #
      # === Parameters
      #
      # [cache_name (String)] uniquely identifies a cache file
      #
      # === Raises
      #
      # [CarrierWave::InvalidParameter] if the cache_name is incorrectly formatted.
      #
      def retrieve_from_cache!(cache_name)
        with_callbacks(:retrieve_from_cache, cache_name) do
          self.cache_id, self.original_filename = cache_name.to_s.split('/', 2)
          @filename = original_filename
          @file = CarrierWave::SanitizedFile.new(cache_path)
        end
      end

    private

      def cache_path
        File.expand_path(File.join(cache_dir, cache_name), root)
      end

      attr_reader :cache_id, :original_filename

      # We can override the full_original_filename method in other modules
      alias_method :full_original_filename, :original_filename

      def cache_id=(cache_id)
        raise CarrierWave::InvalidParameter, "invalid cache id" unless cache_id =~ /\A[\d]{8}\-[\d]{4}\-[\d]+\-[\d]{4}\z/
        @cache_id = cache_id
      end

      def original_filename=(filename)
        raise CarrierWave::InvalidParameter, "invalid filename" if filename =~ CarrierWave::SanitizedFile.sanitize_regexp
        @original_filename = filename
      end

    end # Cache
  end # Uploader
end # CarrierWave
