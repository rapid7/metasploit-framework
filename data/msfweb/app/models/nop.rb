class Nop
  
	def self.get_available()
		mods = []
		$msframework.nops.each_module { |n,m| mods << m.new }
		mods
	end
  
end
