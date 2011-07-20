##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Multi Manage Post Module Resource file Automation',
				'Description'   => %q{
						Execute a resource file containing post modules and options
					against specific sessions.
				},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision$'
			))
		register_options(
			[
				OptPath.new('RESOURCE', [true, "Resource file with space-separated values in the form of: '<session> <module> <options>'"])
			], self.class)
		deregister_options("SESSION")
	end

	# Run Method for when run command is issued
	def run
		entries = []
		current_sessions = framework.sessions.keys.sort
		script = datastore['RESOURCE']
		if ::File.exist?(script)
			::File.open(script, "r").each_line do |line|
				# Empty line
				next if line.strip.length < 1
				# Comment
				next if line[0,1] == "#"
				entries << line.chomp
			end
		else
			print_error("Resource file does not exist.")
		end

		if entries
			entries.each do |l|
				values = l.split(" ")
				sessions = values[0]
				if values[1] =~ /^post/
					post_mod = values[1].gsub(/^post\//,"")
				else
					post_mod = values[1]
				end

				if values.length == 3
					mod_opts = values[2].split(",")
				end
				print_status("Loading #{post_mod}")
				m= framework.post.create(post_mod)
				if sessions =~ /all/i
					session_list = m.compatible_sessions
				else
					session_list = sessions.split(",")
				end
				if session_list
					session_list.each do |s|
						next if not current_sessions.include?(s.to_i)
						if m.session_compatible?(s.to_i)
							print_status("Running against #{s}")
							m.datastore['SESSION'] = s.to_i
							if mod_opts
								mod_opts.each do |o|
									opt_pair = o.split("=",2)
									print_status("\tSetting option #{opt_pair[0]} to #{opt_pair[1]}")
									m.datastore[opt_pair[0]] = opt_pair[1]
								end
							end
							m.options.validate(m.datastore)
							m.run_simple(
								'LocalInput'    => self.user_input,
								'LocalOutput'    => self.user_output
							)
						else
							print_error("Session #{s} is not compatible with #{post_mod}")
						end
					end
				else
					print_error("No compatible sessions were found")
				end
			end
		end
	end


end

