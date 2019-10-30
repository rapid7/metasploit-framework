# -*- coding: binary -*-

module Rex
  module Proto
    module Mms
      module Model
        class Message

          # @!attribute message
          #   @return [String] The text message
          attr_accessor :message

          # @!attribute content_type
          #   @return [Fixnum] The content type of the attachment
          attr_accessor :content_type

          # @!attribute attachment
          #   @return [String] The loaded attachment converted to Base64
          attr_accessor :attachment

          # @!attribute from
          #   @return [String] The from field in the email
          attr_accessor :from

          # @!attribute to
          #   @return [String] The to field in the email
          attr_accessor :to

          # @!attribute subject
          #   @return [String] The subject of the email
          attr_accessor :subject

          # @!attribute attachment_name
          #   @return [String] The attachment base name extracted from :attachment
          attr_accessor :attachment_name


          # Initializes the SMTP object.
          #
          # @param [Hash] opts
          # @option opts [String] :from
          # @option opts [String] :to
          # @option opts [String] :message
          # @option opts [String] :content_type
          # @option opts [String] :attachment_path
          #
          # @return [Rex::Proto::Mms::Model::Message]
          def initialize(opts={})
            self.from = opts[:from]
            self.to = opts[:to]
            self.message = opts[:message]
            self.subject = opts[:subject]
            self.content_type = opts[:content_type]
            if opts[:attachment_path]
              self.attachment = load_file_to_base64(opts[:attachment_path])
              self.attachment_name = File.basename(opts[:attachment_path])
            end
          end


          # Returns the raw MMS message
          #
          # @return [String]
          def to_s
            generate_mms_message
          end


          private


          # Returns the loaded file in Base64 format
          #
          # @return [String] Base64 data
          def load_file_to_base64(path)
            buf = File.read(path)
            (Rex::Text.encode_base64(buf).scan(/.{,76}/).flatten * "\n").strip
          end


          # Returns the raw MMS message
          #
          # @return [String]
          def generate_mms_message
            text = Rex::MIME::Message.new
            text.add_part(self.message, 'text/plain; charset=UTF-8', nil)
            body = Rex::MIME::Message.new
            body.add_part(text.to_s, "multipart/alternative; boundary=#{text.bound}", nil)
            if self.attachment
              body.add_part(self.attachment, "#{content_type}; name=\"#{attachment_name}\"", 'base64', "attachment; filename=\"#{attachment_name}\"")
            end

            mms = "MIME-Version: 1.0\n"
            mms << "From: #{self.from}\n"
            mms << "To: #{self.to}\n"
            mms << "Subject: #{self.subject}\n"
            mms << "Content-Type: multipart/mixed; boundary=#{body.bound}\n"
            mms << "\n"
            mms << body.to_s.gsub(/\-\-\r\n\r\n\-\-_/, "--\n--_")

            mms
          end

        end
      end
    end
  end
end
