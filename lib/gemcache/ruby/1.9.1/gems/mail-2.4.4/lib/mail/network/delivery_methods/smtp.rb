module Mail
  # == Sending Email with SMTP
  # 
  # Mail allows you to send emails using SMTP.  This is done by wrapping Net::SMTP in
  # an easy to use manner.
  # 
  # === Sending via SMTP server on Localhost
  # 
  # Sending locally (to a postfix or sendmail server running on localhost) requires
  # no special setup.  Just to Mail.deliver &block or message.deliver! and it will
  # be sent in this method.
  # 
  # === Sending via MobileMe
  # 
  #   Mail.defaults do
  #     delivery_method :smtp, { :address              => "smtp.me.com",
  #                              :port                 => 587,
  #                              :domain               => 'your.host.name',
  #                              :user_name            => '<username>',
  #                              :password             => '<password>',
  #                              :authentication       => 'plain',
  #                              :enable_starttls_auto => true  }
  #   end
  # 
  # === Sending via GMail
  # 
  #   Mail.defaults do
  #     delivery_method :smtp, { :address              => "smtp.gmail.com",
  #                              :port                 => 587,
  #                              :domain               => 'your.host.name',
  #                              :user_name            => '<username>',
  #                              :password             => '<password>',
  #                              :authentication       => 'plain',
  #                              :enable_starttls_auto => true  }
  #   end
  #
  # === Certificate verification
  #
  # When using TLS, some mail servers provide certificates that are self-signed
  # or whose names do not exactly match the hostname given in the address.
  # OpenSSL will reject these by default. The best remedy is to use the correct
  # hostname or update the certificate authorities trusted by your ruby. If
  # that isn't possible, you can control this behavior with
  # an :openssl_verify_mode setting. Its value may be either an OpenSSL
  # verify mode constant (OpenSSL::SSL::VERIFY_NONE), or a string containing
  # the name of an OpenSSL verify mode (none, peer, client_once,
  # fail_if_no_peer_cert).
  #
  # === Others 
  # 
  # Feel free to send me other examples that were tricky
  # 
  # === Delivering the email
  # 
  # Once you have the settings right, sending the email is done by:
  # 
  #   Mail.deliver do
  #     to 'mikel@test.lindsaar.net'
  #     from 'ada@test.lindsaar.net'
  #     subject 'testing sendmail'
  #     body 'testing sendmail'
  #   end
  # 
  # Or by calling deliver on a Mail message
  # 
  #   mail = Mail.new do
  #     to 'mikel@test.lindsaar.net'
  #     from 'ada@test.lindsaar.net'
  #     subject 'testing sendmail'
  #     body 'testing sendmail'
  #   end
  # 
  #   mail.deliver!
  class SMTP

    def initialize(values)
      self.settings = { :address              => "localhost",
                        :port                 => 25,
                        :domain               => 'localhost.localdomain',
                        :user_name            => nil,
                        :password             => nil,
                        :authentication       => nil,
                        :enable_starttls_auto => true,
                        :openssl_verify_mode  => nil,
                        :ssl                  => nil,
                        :tls                  => nil
                      }.merge!(values)
    end
    
    attr_accessor :settings
    
    # Send the message via SMTP.
    # The from and to attributes are optional. If not set, they are retrieve from the Message.
    def deliver!(mail)

      # Set the envelope from to be either the return-path, the sender or the first from address
      envelope_from = mail.return_path || mail.sender || mail.from_addrs.first
      if envelope_from.blank?
        raise ArgumentError.new('A sender (Return-Path, Sender or From) required to send a message') 
      end
      
      destinations ||= mail.destinations if mail.respond_to?(:destinations) && mail.destinations
      if destinations.blank?
        raise ArgumentError.new('At least one recipient (To, Cc or Bcc) is required to send a message') 
      end
      
      message ||= mail.encoded if mail.respond_to?(:encoded)
      if message.blank?
        raise ArgumentError.new('A encoded content is required to send a message')
      end
      
      smtp = Net::SMTP.new(settings[:address], settings[:port])
      if settings[:tls] || settings[:ssl]
        if smtp.respond_to?(:enable_tls)
          unless settings[:openssl_verify_mode]
            smtp.enable_tls
          else
            openssl_verify_mode = settings[:openssl_verify_mode]
            if openssl_verify_mode.kind_of?(String)
              openssl_verify_mode = "OpenSSL::SSL::VERIFY_#{openssl_verify_mode.upcase}".constantize
            end
            context = Net::SMTP.default_ssl_context
            context.verify_mode = openssl_verify_mode
            smtp.enable_tls(context)
          end        
        end
      elsif settings[:enable_starttls_auto]
        if smtp.respond_to?(:enable_starttls_auto) 
          unless settings[:openssl_verify_mode]
            smtp.enable_starttls_auto
          else
            openssl_verify_mode = settings[:openssl_verify_mode]
            if openssl_verify_mode.kind_of?(String)
              openssl_verify_mode = "OpenSSL::SSL::VERIFY_#{openssl_verify_mode.upcase}".constantize
            end
            context = Net::SMTP.default_ssl_context
            context.verify_mode = openssl_verify_mode
            smtp.enable_starttls_auto(context)
          end
        end
      end
      
      response = nil
      smtp.start(settings[:domain], settings[:user_name], settings[:password], settings[:authentication]) do |smtp_obj|
        response = smtp_obj.sendmail(message, envelope_from, destinations)
      end

      return settings[:return_response] ? response : self
    end
    
    
  end
end
