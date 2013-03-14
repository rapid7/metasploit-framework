# encoding: utf-8

module CarrierWave
  module Storage

    ##
    # File storage stores file to the Filesystem (surprising, no?). There's really not much
    # to it, it uses the store_dir defined on the uploader as the storage location. That's
    # pretty much it.
    #
    class File < Abstract

      ##
      # Move the file to the uploader's store path.
      #
      # By default, store!() uses copy_to(), which operates by copying the file
      # from the cache to the store, then deleting the file from the cache.
      # If move_to_store() is overriden to return true, then store!() uses move_to(),
      # which simply moves the file from cache to store.  Useful for large files.
      #
      # === Parameters
      #
      # [file (CarrierWave::SanitizedFile)] the file to store
      #
      # === Returns
      #
      # [CarrierWave::SanitizedFile] a sanitized file
      #
      def store!(file)
        path = ::File.expand_path(uploader.store_path, uploader.root)
        if uploader.move_to_store
          file.move_to(path, uploader.permissions)
        else
          file.copy_to(path, uploader.permissions)
        end
      end

      ##
      # Retrieve the file from its store path
      #
      # === Parameters
      #
      # [identifier (String)] the filename of the file
      #
      # === Returns
      #
      # [CarrierWave::SanitizedFile] a sanitized file
      #
      def retrieve!(identifier)
        path = ::File.expand_path(uploader.store_path(identifier), uploader.root)
        CarrierWave::SanitizedFile.new(path)
      end

    end # File
  end # Storage
end # CarrierWave
