class Encoder
	def self.find_all()
		mods = []
		$msframework.encoders.each_module { |n,m| mods << m.new }
		mods
	end
end
