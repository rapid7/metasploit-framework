class Auxiliary
	def self.find_all()
		mods = []
		$msframework.auxiliary.each_module { |n,m| mods << m.new }
		mods
	end
end
