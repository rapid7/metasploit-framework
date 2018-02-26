# -*- coding: binary -*-

module Rex
  module Proto
    module Sms
      module Model
        class Message

          # @!attribute message
          #   @return [String] The text message
          attr_accessor :message


          # @!attribute from
          #   @return [String] The from field in the email
          attr_accessor :from

          # @!attribute to
          #   @return [String] The to field in the email
          attr_accessor :to

          # @!attribute subject
          #   @return [String] The subject of the email
          attr_accessor :subject


          # Initializes the SMTP object.
          #
          # @param [Hash] opts
          # @option opts [String] :from
          # @option opts [String] :to
          # @option opts [String] :message
          #
          # @return [Rex::Proto::Sms::Model::Message]
          def initialize(opts={})
            self.from = opts[:from]
            self.to = opts[:to]
            self.message = opts[:message]
            self.subject = opts[:subject]
          end


          # Returns the raw SMS message
          #
          # @return [String]
          def to_s
            body = Rex::MIME::Message.new
            body.add_part(self.message, 'text/plain; charset=UTF-8', nil)

            sms = "MIME-Version: 1.0\n"
            sms << "From: #{self.from}\n"
            sms << "To: #{self.to}\n"
            sms << "Subject: #{self.subject}\n"
            sms << "Content-Type: multipart/alternative; boundary=#{body.bound}\n"
            sms << "\n"
            sms << body.to_s

            sms
          end

        end
      end
    end
  end
end
