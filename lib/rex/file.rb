module Rex

###
#
# This class provides helper mehods for dealing with files that are not
# supplied by the standard ruby API.
#
###
module FileUtils

	#
	# This method searches the PATH environment variable for
	# a fully qualified path to the supplied file name.
	#
	def self.find_full_path(file_name)
		if (ENV['PATH'])
			ENV['PATH'].split(':').each { |base|
				begin
					path = base + ::File::SEPARATOR + file_name
					if (::File::Stat.new(path))
						return path
					end
				rescue
				end
			}
		end

		return nil
	end

end

end
