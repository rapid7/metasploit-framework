# encoding: utf-8
require 'mail/fields/common/parameter_hash'

module Mail
  class ContentDispositionField < StructuredField
    
    FIELD_NAME = 'content-disposition'
    CAPITALIZED_FIELD = 'Content-Disposition'
    
    def initialize(value = nil, charset = 'utf-8')
      self.charset = charset
      super(CAPITALIZED_FIELD, strip_field(FIELD_NAME, value), charset)
      self.parse
      self
    end
    
    def parse(val = value)
      unless val.blank?
        @element = Mail::ContentDispositionElement.new(val)
      end
    end
    
    def element
      @element ||= Mail::ContentDispositionElement.new(value)
    end

    def disposition_type
      element.disposition_type
    end
    
    def parameters
      @parameters = ParameterHash.new
      element.parameters.each { |p| @parameters.merge!(p) }
      @parameters
    end

    def filename
      case
      when !parameters['filename'].blank?
        @filename = parameters['filename']
      when !parameters['name'].blank?
        @filename = parameters['name']
      else 
        @filename = nil
      end
      @filename
    end

    # TODO: Fix this up
    def encoded
      if parameters.length > 0
        p = ";\r\n\s#{parameters.encoded}\r\n"
      else
        p = "\r\n"
      end
      "#{CAPITALIZED_FIELD}: #{disposition_type}" + p
    end
    
    def decoded
      if parameters.length > 0
        p = "; #{parameters.decoded}"
      else
        p = ""
      end
      "#{disposition_type}" + p
    end

  end
end
