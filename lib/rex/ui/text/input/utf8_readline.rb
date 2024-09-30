# -*- coding: binary -*-

require 'rex/ui/text/input/utf8_common'

module Rex
module Ui
module Text

###
#
# This class implements standard input using Reline against
# standard input, and forces UTF-8 encoding. It supports tab completion.
#
###
class Input::Utf8Readline < Input::Readline

  # Array of methods that will be used to override methods from the base class to wrap them with forced UTF-8 encoding.
  METHODS_TO_WRAP_WITH_UTF8_ENCODING = %i[pgets gets sysread readline_with_output update_prompt].freeze

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
