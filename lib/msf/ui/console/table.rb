
module Msf
module Ui
module Console

###
#
# Table
# -----
#
# Console table display wrapper that allows for stylized tables
#
###
class Table < Rex::Ui::Text::Table

	# Default table styles
	module Style
		Default = 0
	end

	def initialize(style, opts = {})
		if (style == Style::Default)
			opts['Indent']  = 3
			opts['Prefix']  = "\n\n"
			opts['Postfix'] = "\n\n"

			super(opts)
		end
	end

end

end
end
end
