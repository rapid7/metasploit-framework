class Payload

	def self.get_available()
		mods = []
		$msframework.payloads.each_module { |n,m| mods << m.new }
		mods
	end

end
