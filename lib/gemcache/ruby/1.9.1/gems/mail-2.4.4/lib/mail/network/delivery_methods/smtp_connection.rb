module Mail
  # == Sending Email with SMTP
  # 
  # Mail allows you to send emails using an open SMTP connection.  This is done by
  # passing a created Net::SMTP object.  This way we can get better performance to
  # our local mail server by reducing the number of connections at any one time.
  #
  # === Sending via SMTP server on Localhost
  # 
  # To send mail open a connection with Net::Smtp using any options you like
  # === Delivering the email
  # 
  # Once you have the settings right, sending the email is done by:
  #
  #   smtp_conn = Net::SMTP.start(settings[:address], settings[:port])
  #   Mail.defaults do
  #     delivery_method :smtp_connection, { :connection => smtp_conn }
  #   end
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
  class SMTPConnection

    def initialize(values)
      raise ArgumentError.new('A Net::SMTP object is required for this delivery method') if values[:connection].nil?
      self.smtp = values[:connection]
      self.settings = values
    end
    
    attr_accessor :smtp
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
            
      response = smtp.sendmail(message, envelope_from, destinations)
      
      settings[:return_response] ? response : self 
    end
        
  end
end
