# encoding: utf-8
# 
#    The field names of any optional-field MUST NOT be identical to any
#    field name specified elsewhere in this standard.
# 
# optional-field  =       field-name ":" unstructured CRLF
require 'mail/fields/unstructured_field'

module Mail
  class OptionalField < UnstructuredField
    
  end
end
