module Rex
module Ui
module Text
	autoload :Input,  'rex/ui/text/input'
	autoload :Output, 'rex/ui/text/output'
	autoload :Color,  'rex/ui/text/color'
	autoload :Table,  'rex/ui/text/table'
	
	autoload :PseudoShell,     'rex/ui/text/shell'
	autoload :Shell,           'rex/ui/text/shell'
	autoload :DispatcherShell, 'rex/ui/text/dispatcher_shell'
	autoload :IrbShell,        'rex/ui/text/irb_shell'

	autoload :ProgressTracker, 'rex/ui/text/progress_tracker'
end
end
end
