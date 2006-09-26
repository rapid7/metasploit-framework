class Auxiliary
	def self.get_available() 	
		mods = []
		$msframework.auxiliary.each_module { |n,m| mods << m.new }
		mods
	end
end
