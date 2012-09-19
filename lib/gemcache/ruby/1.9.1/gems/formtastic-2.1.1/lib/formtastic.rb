# encoding: utf-8
require 'formtastic/engine' if defined?(::Rails)

module Formtastic
  extend ActiveSupport::Autoload

  autoload :FormBuilder
  autoload :Helpers
  autoload :HtmlAttributes
  autoload :I18n
  autoload :Inputs
  autoload :Actions
  autoload :LocalizedString
  autoload :Localizer
  autoload :Util
  
  # @private
  class UnknownInputError < NameError
  end
  
  # @private
  class UnknownActionError < NameError
  end
  
  # @private
  class PolymorphicInputWithoutCollectionError < ArgumentError
  end
  
  # @private
  class UnsupportedMethodForAction < ArgumentError
  end

end
