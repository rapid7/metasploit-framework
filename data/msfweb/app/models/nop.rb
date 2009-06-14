class Nop
	def self.find_all()
		mods = []
		$msframework.nops.each_module { |n,m| mods << m.new }
		mods
	end
end
