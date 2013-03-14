# encoding: utf-8
# 
# = Carbon Copy Field
# 
# The Cc field inherits from StructuredField and handles the Cc: header
# field in the email.
# 
# Sending cc to a mail message will instantiate a Mail::Field object that
# has a CcField as it's field type.  This includes all Mail::CommonAddress
# module instance metods.
# 
# Only one Cc field can appear in a header, though it can have multiple
# addresses and groups of addresses.
# 
# == Examples:
# 
#  mail = Mail.new
#  mail.cc = 'Mikel Lindsaar <mikel@test.lindsaar.net>, ada@test.lindsaar.net'
#  mail.cc    #=> ['Mikel Lindsaar <mikel@test.lindsaar.net>', 'ada@test.lindsaar.net']
#  mail[:cc]  #=> '#<Mail::Field:0x180e5e8 @field=#<Mail::CcField:0x180e1c4
#  mail['cc'] #=> '#<Mail::Field:0x180e5e8 @field=#<Mail::CcField:0x180e1c4
#  mail['Cc'] #=> '#<Mail::Field:0x180e5e8 @field=#<Mail::CcField:0x180e1c4
# 
#  mail[:cc].encoded   #=> 'Cc: Mikel Lindsaar <mikel@test.lindsaar.net>, ada@test.lindsaar.net\r\n'
#  mail[:cc].decoded   #=> 'Mikel Lindsaar <mikel@test.lindsaar.net>, ada@test.lindsaar.net'
#  mail[:cc].addresses #=> ['mikel@test.lindsaar.net', 'ada@test.lindsaar.net']
#  mail[:cc].formatted #=> ['Mikel Lindsaar <mikel@test.lindsaar.net>', 'ada@test.lindsaar.net']
# 
require 'mail/fields/common/common_address'

module Mail
  class CcField < StructuredField
    
    include Mail::CommonAddress
    
    FIELD_NAME = 'cc'
    CAPITALIZED_FIELD = 'Cc'
    
    def initialize(value = nil, charset = 'utf-8')
      self.charset = charset
      super(CAPITALIZED_FIELD, strip_field(FIELD_NAME, value), charset)
      self.parse
      self
    end
    
    def encoded
      do_encode(CAPITALIZED_FIELD)
    end
    
    def decoded
      do_decode
    end
    
  end
end
