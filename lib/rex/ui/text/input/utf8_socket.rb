# -*- coding: binary -*-

require 'rex/ui/text/input/utf8_common'

module Rex
module Ui
module Text

###
#
# This class implements input against a socket and forces UTF-8 encoding.
#
###
class Input::Utf8Socket < Rex::Ui::Text::Input::Socket

  # Array of methods that will be used to override methods from the base class to wrap them with forced UTF-8 encoding.
  METHODS_TO_WRAP_WITH_UTF8_ENCODING = %i[sysread gets].freeze

  METHODS_TO_WRAP_WITH_UTF8_ENCODING.each do |method|
    class_eval %{
      def #{method} (*args, &block)
        Rex::Ui::Text::Input::Utf8Common.with_utf8_encoding do
          super
        end
      end
    }
  end

  def utf8?
    true
  end
end

end
end
end
