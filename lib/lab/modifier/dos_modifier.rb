# This assumes you're on a recent ubuntu
# TODO - enforce this, or split it out...

module Lab
module Modifier
module Dos

	def ping(target)
		run_command("ping #{filter_input(target)}")
	end

end
end
end
