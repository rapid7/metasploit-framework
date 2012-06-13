# encoding: utf-8

require 'open-uri'

module CarrierWave
  module Uploader
    module Download
      extend ActiveSupport::Concern

      include CarrierWave::Uploader::Callbacks
      include CarrierWave::Uploader::Configuration
      include CarrierWave::Uploader::Cache

      class RemoteFile
        def initialize(uri)
          @uri = uri
        end

        def original_filename
          File.basename(file.base_uri.path)
        end

        def respond_to?(*args)
          super or file.respond_to?(*args)
        end

        def http?
          @uri.scheme =~ /^https?$/
        end

      private

        def file
          if @file.blank?
            @file = Kernel.open(@uri.to_s)
            @file = @file.is_a?(String) ? StringIO.new(@file) : @file
          end
          @file
        end

        def method_missing(*args, &block)
          file.send(*args, &block)
        end
      end

      ##
      # Caches the file by downloading it from the given URL.
      #
      # === Parameters
      #
      # [url (String)] The URL where the remote file is stored
      #
      def download!(uri)
        unless uri.blank?
          processed_uri = process_uri(uri)
          file = RemoteFile.new(processed_uri)
          raise CarrierWave::DownloadError, "trying to download a file which is not served over HTTP" unless file.http?
          cache!(file)
        end
      end

      ##
      # Processes the given URL by parsing and escaping it. Public to allow overriding.
      #
      # === Parameters
      #
      # [url (String)] The URL where the remote file is stored
      #
      def process_uri(uri)
        URI.parse(URI.escape(URI.unescape(uri)).gsub("[", "%5B").gsub("]", "%5D").gsub("+", "%2B"))
      end

    end # Download
  end # Uploader
end # CarrierWave
