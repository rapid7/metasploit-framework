#
# This file includes everything needed to interact with the user interface
# wrappers of the rex library.
#

require 'rex'

module Rex
module Ui
	# General classes
	autoload :Output,          'rex/ui/output'
	autoload :ProgressTracker, 'rex/ui/progress_tracker'

	# Text-based user interfaces
	autoload :Text, 'rex/ui/text'

	# Ui subscriber
	autoload :Subscriber,  'rex/ui/subscriber'
	autoload :Interactive, 'rex/ui/interactive'
end
end
