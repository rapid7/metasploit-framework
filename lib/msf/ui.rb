module Msf
module UiEventSubscriber
	def on_ui_command(line)
	end

	def on_ui_stop()
	end

	def on_ui_start()
	end
end

module Ui
end
end

require 'rex/ui'
require 'msf/ui/banner'
require 'msf/ui/driver'
require 'msf/ui/common'
require 'msf/ui/console'
