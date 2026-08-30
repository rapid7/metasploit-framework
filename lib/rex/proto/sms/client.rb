# -*- coding: binary -*-

module Rex
  module Proto
    module Sms
      class Client

        # @!attribute carrier
        #   @return [Symbol] The service provider for the phone numbers.
        attr_accessor :carrier

        # @!attribute smtp_server
        #   @return [Rex::Proto::Sms::Model::Smtp] The Smtp object with the Smtp settings.
        attr_accessor :smtp_server


        # Initializes the Client object.
        #
        # @param [Hash] opts
        # @option opts [Symbol] Service provider name (see Rex::Proto::Sms::Model::GATEWAYS)
        # @option opts [Rex::Proto::Sms::Model::Smtp] SMTP object
        #
        # @return [Rex::Proto::Sms::Client]
        def initialize(opts={})
          self.carrier       = opts[:carrier]
          self.smtp_server   = opts[:smtp_server]

          validate_carrier!
        end


        # Sends a text to multiple recipients.
        #
        # @param phone_numbers [<String>Array] An array of phone numbers.
        # @param subject [String] Subject of the message
        # @param message [String] The text message to send.
        #
        # @return [void]
        def send_text_to_phones(phone_numbers, subject, message)
          carrier     = Rex::Proto::Sms::Model::GATEWAYS[self.carrier]
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
                sms_message = Rex::Proto::Sms::Model::Message.new(
                  from: from,
                  to: r,
                  subject: subject,
                  message: message
                )
                smtp.send_message(sms_message.to_s, from, r)
              end
            end
          rescue Net::SMTPAuthenticationError => e
            raise Rex::Proto::Sms::Exception, e.message
          ensure
            smtp.finish if smtp && smtp.started?
          end
        end


        private


        # Validates the carrier parameter.
        #
        # @raise [Rex::Proto::Sms::Exception] If an invalid service provider is used.
        def validate_carrier!
          unless Rex::Proto::Sms::Model::GATEWAYS.include?(self.carrier)
            raise Rex::Proto::Sms::Exception, 'Invalid carrier.'
          end
        end

      end
    end
  end
end
