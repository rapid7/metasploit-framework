# -*- coding: binary -*-

###
#
# The Msf::Auxiliary::Mms mixin allows you to send a text message
# including a media file.
#
##

module Msf
  module Auxiliary::Mms

    def initialize(info={})
      super

      register_options(
        [
          OptString.new('SMTPFROM', [false, 'The FROM field for SMTP', '']),
          OptString.new('SMTPADDRESS', [ true, 'The SMTP server to use to send the text messages']),
          OptString.new('MMSSUBJECT', [false, 'The Email subject', '']),
          OptPort.new('SMTPPORT', [true, 'The SMTP port to use to send the text messages', 25]),
          OptString.new('SMTPUSERNAME', [true, 'The SMTP account to use to send the text messages']),
          OptString.new('SMTPPASSWORD', [true, 'The SMTP password to use to send the text messages']),
          OptEnum.new('MMSCARRIER', [true, 'The targeted MMS service provider', nil,Rex::Proto::Mms::Model::GATEWAYS.keys.collect { |k| k.to_s }]),
          OptString.new('CELLNUMBERS', [true, 'The phone numbers to send to']),
          OptString.new('TEXTMESSAGE', [true, 'The text message to send']),
          OptPath.new('MMSFILE', [false, 'The attachment to include in the text file']),
          OptString.new('MMSFILECTYPE', [false, 'The attachment content type'])
        ], Auxiliary::Mms)

      register_advanced_options(
        [
          OptEnum.new('SmtpLoginType', [true, 'The SMTP login type', 'login', ['plain', 'login', 'cram_md5']]),
          OptString.new('HeloDdomain', [false, 'The domain to use for HELO', ''])
        ], Auxiliary::Mms)
    end


    # Sends an MMS message to multiple numbers of the same service provider (carrier).
    #
    # @example This sends a text (including an attachment) via Gmail
    #   smtp = Rex::Proto::Mms::Model::Smtp.new(address: 'smtp.gmail.com', port: 587, username: user, password: pass)
    #   mms = Rex::Proto::Mms::Client.new(carrier: :verizon, smtp_server: smtp)
    #   mms.send_mms_to_phones(numbers, 'hello world?', '/tmp/test.jpg', 'image/jpeg')
    #
    # @param phone_numbers [<String>Array] An array of numbers of try (of the same carrier)
    # @param subject [String] MMS subject
    # @param message [String] The text to send.
    # @param attachment_path [String] Optional
    # @param ctype [String] Optional
    #
    # @return [void]
    def send_mms(phone_numbers, subject, message, attachment_path=nil, ctype=nil)
      smtp = Rex::Proto::Mms::Model::Smtp.new(
        address: datastore['SMTPADDRESS'],
        port: datastore['SMTPPORT'],
        username: datastore['SMTPUSERNAME'],
        password: datastore['SMTPPASSWORD'],
        login_type: datastore['SmtpLoginType'].to_sym,
        from: datastore['SMTPFROM'],
      )

      carrier = datastore['MMSCARRIER'].to_sym
      mms = Rex::Proto::Mms::Client.new(carrier: carrier, smtp_server: smtp)
      mms.send_mms_to_phones(phone_numbers, subject, message, attachment_path, ctype)
    end

  end
end
