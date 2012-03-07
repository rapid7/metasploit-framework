module Msf
class Post
module Unix
	include ::Msf::Post::Common

	# returns all user directories found
	def enum_user_directories
		user_dirs = []

		# get all user directories from /etc/passwd
		read_file("/etc/passwd").each_line do |passwd_line|
			user_dirs << passwd_line.split(/:/)[5]
		end

		# also list other common places for home directories in the event that
		# the users aren't in /etc/passwd (LDAP, for example)
		case session.platform
		when 'osx'
			user_dirs << cmd_exec('ls /Users').each_line.map { |l| "/Users/#{l}" }
		else
			user_dirs << cmd_exec('ls /home').each_line.map { |l| "/home/#{l}" }
		end

		user_dirs.flatten!
		user_dirs.sort!
		user_dirs.uniq!
		user_dirs.compact!

		user_dirs
	end
end
end
end
