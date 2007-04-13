module Msf

class Auxiliary::BhAux < Msf::Auxiliary

	def initialize
		super(
			'Name'        => "BlackHat Training Auxiliary Module",
			'Description' => "Example Auxiliary Module",
			'Author'      => "skape",
			'License'     => MSF_LICENSE)
	end

	def run
		print_status("Inside run...")
	end
	
end

end
