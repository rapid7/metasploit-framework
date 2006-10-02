class Payload
	def self.find_all()
		mods = []
		$msframework.payloads.each_module { |n,m| mods << m.new }
		mods
	end
	
	def self.create(refname)
	    modinst = $msframework.payloads.create(refname)
        modinst
	end
end
