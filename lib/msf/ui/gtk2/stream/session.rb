module Msf
module Ui
module Gtk2
module Stream

class Session
	
	def initialize(buffer, session_tree, options, session, input, output)
		
		@session_tree = session_tree
		@session = session
		
		@session_tree.add_session(@session, options, buffer, input, output)
	end
end

end
end
end
end

