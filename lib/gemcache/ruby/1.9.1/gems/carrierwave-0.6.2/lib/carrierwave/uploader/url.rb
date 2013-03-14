# encoding: utf-8

module CarrierWave
  module Uploader
    module Url
      extend ActiveSupport::Concern
      include CarrierWave::Uploader::Configuration

      ##
      # === Parameters
      #
      # [Hash] optional, the query params (only AWS)
      #
      # === Returns
      #
      # [String] the location where this file is accessible via a url
      #
      def url(options = {})
        if file.respond_to?(:url) and not file.url.blank?
          file.method(:url).arity == 0 ? file.url : file.url(options)
        elsif current_path
          (base_path || "") + File.expand_path(current_path).gsub(File.expand_path(root), '')
        end
      end

      def to_s
        url || ''
      end

    end # Url
  end # Uploader
end # CarrierWave
