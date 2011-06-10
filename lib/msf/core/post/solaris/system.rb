require 'msf/core/post/common'
require 'msf/core/post/file'

module Msf
class Post

module System
	include ::Msf::Post::Common
		include ::Msf::Post::File

		# Returns a Hash containing Distribution Name, Version and Kernel Information
		def get_sysinfo
			system_data = {}
			kernel_version = cmd_exec("uname -a")
			version = read_file("/etc/release").split("\n")[0].strip
			system_data[:version] = version
			system_data[:kernel] = kernel_version
			system_data[:hostname] = kernel_version.split(" ")[1]
			return system_data
		end

		# Returns an array of hashes each representing a user
		# Keys are name, uid, gid, info, dir and shell
		def get_users
			users = []
			cmd_out = cmd_exec("cat /etc/passwd").split("\n")
			cmd_out.each do |l|
				entry = {}
				user_field = l.split(":")
				entry[:name] = user_field[0]
				entry[:uid] = user_field[2]
				entry[:gid] = user_field[3]
				entry[:info] = user_field[4]
				entry[:dir] = user_field[5]
				entry[:shell] = user_field[6]
				users << entry
			end
			return users
		end

		# Returns an array of hashes each hash representing a user group
		# Keys are name, gid and users
		def get_groups
			groups = []
			cmd_out = cmd_exec("cat /etc/group").split("\n")
			cmd_out.each do |l|
				entry = {}
				user_field = l.split(":")
				entry[:name] = user_field[0]
				entry[:gid] = user_field[2]
				entry[:users] = user_field[3]
				groups << entry
			end
			return groups
		end


end # System
end # Post
end # Msf
