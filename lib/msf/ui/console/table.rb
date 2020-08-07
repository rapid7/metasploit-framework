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

  def self.new(*args, &block)
    style, opts = args

    if style == Style::Default
      opts['Indent']  = 3
      if (!opts['Prefix'])
        opts['Prefix']  = "\n"
      end
      if (!opts['Postfix'])
        opts['Postfix'] = "\n"
      end
    end

    instance = super(opts, &block)
    if style == Style::Default
      instance.extend(DefaultStyle)
    end
    instance
  end

  module DefaultStyle
    #
    # Print nothing if there are no rows if the style is default.
    #
    def to_s
      return '' if (rows.length == 0)

      super
    end
  end
end
end
end
end
