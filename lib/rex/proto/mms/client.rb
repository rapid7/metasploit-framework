# -*- coding: binary -*-

module Rex
  module Proto
    module Mms
      class Client

        # @!attribute carrier
        #   @return [Symbol] The service provider for the phone numbers.
        attr_accessor :carrier

        # @!attribute smtp_server
        #   @return [Rex::Proto::Mms::Model::Smtp] The Smtp object with the Smtp settings.
        attr_accessor :smtp_server


        # Initializes the Client object.
        #
        # @param [Hash] opts
        # @option opts [Symbol] Service provider name (see Rex::Proto::Mms::Model::GATEWAYS)
        # @option opts [Rex::Proto::mms::Model::Smtp] SMTP object
        #
        # @return [Rex::Proto::Mms::Client]
        def initialize(opts={})
          self.carrier     = opts[:carrier]
          self.smtp_server = opts[:smtp_server]

          validate_carrier!
        end


        # Sends a media text to multiple recipients.
        #
        # @param phone_numbers [<String>Array] An array of phone numbers.
        # @param subject [String] MMS subject
        # @param message [String] The message to send.
        # @param attachment_path [String] (Optional) The attachment to include
        # @param ctype [String] (Optional) The content type to use for the attachment
        #
        # @return [void]
        def send_mms_to_phones(phone_numbers, subject, message, attachment_path=nil, ctype=nil)
          carrier     = Rex::Proto::Mms::Model::GATEWAYS[self.carrier]
          recipients  = phone_numbers.collect { |p| "#{p}@#{carrier}" }
          address     = self.smtp_server.address
          port        = self.smtp_server.port
          username    = self.smtp_server.username
          password    = self.smtp_server.password
          helo_domain = self.smtp_server.helo_domain
          login_type  = self.smtp_server.login_type
          from        = self.smtp_server.from

          smtp = Net::SMTP.new(address, port)

          begin
            smtp.enable_starttls_auto
            smtp.start(helo_domain, username, password, login_type) do
              recipients.each do |r|
                mms_message = Rex::Proto::Mms::Model::Message.new(
                  message: message,
                  content_type: ctype,
                  attachment_path: attachment_path,
                  from: from,
                  to: r,
                  subject: subject
                )
                smtp.send_message(mms_message.to_s, from, r)
              end
            end
          rescue Net::SMTPAuthenticationError => e
            raise Rex::Proto::Mms::Exception, e.message
          ensure
            smtp.finish if smtp && smtp.started?
          end
        end


        # Validates the carrier parameter.
        #
        # @raise [Rex::Proto::Mms::Exception] If an invalid service provider is used.
        def validate_carrier!
          unless Rex::Proto::Mms::Model::GATEWAYS.include?(self.carrier)
            raise Rex::Proto::Mms::Exception, 'Invalid carrier.'
          end
        end

      end
    end
  end
end
