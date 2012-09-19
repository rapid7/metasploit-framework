# encoding: utf-8
# 
# = Blind Carbon Copy Field
# 
# The Bcc field inherits from StructuredField and handles the Bcc: header
# field in the email.
# 
# Sending bcc to a mail message will instantiate a Mail::Field object that
# has a BccField as it's field type.  This includes all Mail::CommonAddress
# module instance metods.
# 
# Only one Bcc field can appear in a header, though it can have multiple
# addresses and groups of addresses.
# 
# == Examples:
# 
#  mail = Mail.new
#  mail.bcc = 'Mikel Lindsaar <mikel@test.lindsaar.net>, ada@test.lindsaar.net'
#  mail.bcc    #=> ['Mikel Lindsaar <mikel@test.lindsaar.net>', 'ada@test.lindsaar.net']
#  mail[:bcc]  #=> '#<Mail::Field:0x180e5e8 @field=#<Mail::BccField:0x180e1c4
#  mail['bcc'] #=> '#<Mail::Field:0x180e5e8 @field=#<Mail::BccField:0x180e1c4
#  mail['Bcc'] #=> '#<Mail::Field:0x180e5e8 @field=#<Mail::BccField:0x180e1c4
# 
#  mail[:bcc].encoded   #=> ''      # Bcc field does not get output into an email
#  mail[:bcc].decoded   #=> 'Mikel Lindsaar <mikel@test.lindsaar.net>, ada@test.lindsaar.net'
#  mail[:bcc].addresses #=> ['mikel@test.lindsaar.net', 'ada@test.lindsaar.net']
#  mail[:bcc].formatted #=> ['Mikel Lindsaar <mikel@test.lindsaar.net>', 'ada@test.lindsaar.net']
# 
require 'mail/fields/common/common_address'

module Mail
  class BccField < StructuredField
    
    include Mail::CommonAddress
    
    FIELD_NAME = 'bcc'
    CAPITALIZED_FIELD = 'Bcc'
    
    def initialize(value = '', charset = 'utf-8')
      @charset = charset
      super(CAPITALIZED_FIELD, strip_field(FIELD_NAME, value), charset)
      self.parse
      self
    end
    
    # Bcc field should never be :encoded
    def encoded
      ''
    end
    
    def decoded
      do_decode
    end
    
  end
end
