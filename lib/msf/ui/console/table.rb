# -*- coding: binary -*-

module Msf
module Ui
module Console

###
#
# Console table display wrapper that allows for stylized tables
#
###
class Table < Rex::Text::Table

  #
  # Default table styles.
  #
  module Style
    Default = 0
  end

  #
  # Initializes a wrappered table with the supplied style and options.
  #
  def initialize(style, opts = {})
    self.style = style

    if (self.style == Style::Default)
      opts['Indent']  = 3
      if (!opts['Prefix'])
        opts['Prefix']  = "\n"
      end
      if (!opts['Postfix'])
        opts['Postfix'] = "\n"
      end

      super(opts)
    end
  end

  #
  # Print nothing if there are no rows if the style is default.
  #
  def to_s
    if (style == Style::Default)
      return '' if (rows.length == 0)
    end

    super
  end

protected

  attr_accessor :style # :nodoc:

end

end
end
end
