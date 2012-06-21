# encoding: utf-8

module CarrierWave
  module Uploader
    module Proxy

      ##
      # === Returns
      #
      # [Boolean] Whether the uploaded file is blank
      #
      def blank?
        file.blank?
      end

      ##
      # === Returns
      #
      # [String] the path where the file is currently located.
      #
      def current_path
        file.path if file.respond_to?(:path)
      end

      alias_method :path, :current_path

      ##
      # Returns a string that uniquely identifies the last stored file
      #
      # === Returns
      #
      # [String] uniquely identifies a file
      #
      def identifier
        storage.identifier if storage.respond_to?(:identifier)
      end

      ##
      # Read the contents of the file
      #
      # === Returns
      #
      # [String] contents of the file
      #
      def read
        file.read if file.respond_to?(:read)
      end

      ##
      # Fetches the size of the currently stored/cached file
      #
      # === Returns
      #
      # [Integer] size of the file
      #
      def size
        file.respond_to?(:size) ? file.size : 0
      end

      ##
      # Return the size of the file when asked for its length
      #
      # === Returns
      #
      # [Integer] size of the file
      #
      # === Note
      #
      # This was added because of the way Rails handles length/size validations in 3.0.6 and above.
      #
      def length
        size
      end

    end # Proxy
  end # Uploader
end # CarrierWave
