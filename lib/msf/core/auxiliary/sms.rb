# -*- coding: binary -*-

###
#
# The Msf::Auxiliary::Sms mixin allows you to send a text message to
# multiple phones of the same carrier. A valid SMTP server is needed.
#
##

module Msf
  module Auxiliary::Sms

    def initialize(info={})
      super

      register_options(
        [
          OptString.new('SMTPFROM', [false, 'The FROM field for SMTP', '']),
          OptString.new('SMTPADDRESS', [ true, 'The SMTP server to use to send the text messages']),
          OptPort.new('SMTPPORT', [true, 'The SMTP port to use to send the text messages', 25]),
          OptString.new('SMTPUSERNAME', [true, 'The SMTP account to use to send the text messages']),
          OptString.new('SMTPPASSWORD', [true, 'The SMTP password to use to send the text messages']),
          OptEnum.new('SMSCARRIER', [true, 'The targeted SMS service provider', nil,Rex::Proto::Sms::Model::GATEWAYS.keys.collect { |k| k.to_s }]),
          OptString.new('CELLNUMBERS', [true, 'The phone numbers to send to']),
          OptString.new('SMSMESSAGE', [true, 'The text message to send']),
          OptString.new('SMSSUBJECT', [false, 'The text subject', ''])
        ], Auxiliary::Sms)

      register_advanced_options(
        [
          OptEnum.new('SmtpLoginType', [true, 'The SMTP login type', 'login', ['plain', 'login', 'cram_md5']]),
          OptString.new('HeloDdomain', [false, 'The domain to use for HELO', ''])
        ], Auxiliary::Sms)
    end


    # Sends a text message to multiple numbers of the same service provider (carrier).
    #
    # @example This sends a text via Gmail
    #   smtp = Rex::Proto::Sms::Model::Smtp.new(address: 'smtp.gmail.com', port: 587, username: user, password: pass)
    #   sms = Rex::Proto::Sms::Client.new(carrier: :verizon, smtp_server: smtp)
    #   numbers = ['1112223333']
    #   sms.send_text_to_phones(numbers, 'Hello from Gmail')
    #
    # @param phone_numbers [<String>Array] An array of numbers of try (of the same carrier)
    # @param subject [String] The text subject
    # @param message [String] The text to send.
    #
    # @return [void]
    def send_text(phone_numbers, subject, message)
      smtp = Rex::Proto::Sms::Model::Smtp.new(
        address: datastore['SMTPADDRESS'],
        port: datastore['SMTPPORT'],
        username: datastore['SMTPUSERNAME'],
        password: datastore['SMTPPASSWORD'],
        login_type: datastore['SmtpLoginType'].to_sym,
        from: datastore['SMTPFROM']
      )

      carrier = datastore['SMSCARRIER'].to_sym
      sms = Rex::Proto::Sms::Client.new(carrier: carrier, smtp_server: smtp)
      sms.send_text_to_phones(phone_numbers, subject, message)
    end

  end
end
