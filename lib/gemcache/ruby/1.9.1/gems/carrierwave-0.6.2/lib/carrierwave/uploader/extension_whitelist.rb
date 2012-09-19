# encoding: utf-8

module CarrierWave
  module Uploader
    module ExtensionWhitelist
      extend ActiveSupport::Concern

      included do
        before :cache, :check_whitelist!
      end

      ##
      # Override this method in your uploader to provide a white list of extensions which
      # are allowed to be uploaded. Compares the file's extension case insensitive.
      # Furthermore, not only strings but Regexp are allowed as well.
      #
      # When using a Regexp in the white list, `\A` and `\z` are automatically added to
      # the Regexp expression, also case insensitive.
      #
      # === Returns
      #
      # [NilClass, Array[String,Regexp]] a white list of extensions which are allowed to be uploaded
      #
      # === Examples
      #
      #     def extension_white_list
      #       %w(jpg jpeg gif png)
      #     end
      #
      # Basically the same, but using a Regexp:
      #
      #     def extension_white_list
      #       [/jpe?g/, 'gif', 'png']
      #     end
      #
      def extension_white_list; end

    private

      def check_whitelist!(new_file)
        extension = new_file.extension.to_s
        if extension_white_list and not extension_white_list.detect { |item| extension =~ /\A#{item}\z/i }
          raise CarrierWave::IntegrityError, I18n.translate(:"errors.messages.extension_white_list_error", :extension => new_file.extension.inspect, :allowed_types => extension_white_list.inspect)
        end
      end

    end # ExtensionWhitelist
  end # Uploader
end # CarrierWave
