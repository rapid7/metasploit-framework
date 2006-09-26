class Encoder

	def self.get_available() 	
		mods = []
		$msframework.encoders.each_module { |n,m| mods << m.new }
		mods
	end

end
