# encoding: utf-8

module CarrierWave
  module Uploader
    module Store
      extend ActiveSupport::Concern

      include CarrierWave::Uploader::Callbacks
      include CarrierWave::Uploader::Configuration
      include CarrierWave::Uploader::Cache

      ##
      # Override this in your Uploader to change the filename.
      #
      # Be careful using record ids as filenames. If the filename is stored in the database
      # the record id will be nil when the filename is set. Don't use record ids unless you
      # understand this limitation.
      #
      # Do not use the version_name in the filename, as it will prevent versions from being
      # loaded correctly.
      #
      # === Returns
      #
      # [String] a filename
      #
      def filename
        @filename
      end

      ##
      # Calculates the path where the file should be stored. If +for_file+ is given, it will be
      # used as the filename, otherwise +CarrierWave::Uploader#filename+ is assumed.
      #
      # === Parameters
      #
      # [for_file (String)] name of the file <optional>
      #
      # === Returns
      #
      # [String] the store path
      #
      def store_path(for_file=filename)
        File.join([store_dir, full_filename(for_file)].compact)
      end

      ##
      # Stores the file by passing it to this Uploader's storage engine.
      #
      # If new_file is omitted, a previously cached file will be stored.
      #
      # === Parameters
      #
      # [new_file (File, IOString, Tempfile)] any kind of file object
      #
      def store!(new_file=nil)
        cache!(new_file) if new_file && ((@cache_id != parent_cache_id) || @cache_id.nil?)
        if @file and @cache_id
          with_callbacks(:store, new_file) do
            new_file = storage.store!(@file)
            @file.delete if (delete_tmp_file_after_storage && ! move_to_store)
            delete_cache_id
            @file = new_file
            @cache_id = nil
          end
        end
      end

      ##
      # Deletes a cache id (tmp dir in cache)
      #
      def delete_cache_id
        if @cache_id
          path = File.expand_path(File.join(cache_dir, @cache_id), CarrierWave.root)
          begin
            Dir.rmdir(path)
          rescue Errno::ENOENT
            # Ignore: path does not exist
          rescue Errno::ENOTDIR
            # Ignore: path is not a dir
          rescue Errno::ENOTEMPTY, Errno::EEXIST
            # Ignore: dir is not empty
          end
        end
      end

      ##
      # Retrieves the file from the storage.
      #
      # === Parameters
      #
      # [identifier (String)] uniquely identifies the file to retrieve
      #
      def retrieve_from_store!(identifier)
        with_callbacks(:retrieve_from_store, identifier) do
          @file = storage.retrieve!(identifier)
        end
      end

    private

      def full_filename(for_file)
        for_file
      end

      def storage
        @storage ||= self.class.storage.new(self)
      end

    end # Store
  end # Uploader
end # CarrierWave
