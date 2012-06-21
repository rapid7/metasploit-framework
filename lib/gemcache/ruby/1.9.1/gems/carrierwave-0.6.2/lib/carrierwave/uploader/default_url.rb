# encoding: utf-8

module CarrierWave
  module Uploader
    module DefaultUrl

      def url(*args)
        super || default_url
      end

      ##
      # Override this method in your uploader to provide a default url
      # in case no file has been cached/stored yet.
      #
      def default_url; end

    end # DefaultPath
  end # Uploader
end # CarrierWave