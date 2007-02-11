module Msf
module Ui
module Gtk2
module Stream

class Session
	def initialize(session_tree, session)
		session_tree.add_session(session)
	end
end

end
end
end
end

