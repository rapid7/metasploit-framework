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
				'Name'          => 'Multi Manage Post Module Execution Automation',
				'Description'   => %q{ Run the specified module against a a given set
					of sessions or all sessions.},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision$'
			))
		register_options(
			[
				OptString.new('SESSIONS', [true, 'Specify either ALL for all sessions or a comma-separated list of sessions']),
				OptString.new('MODULE', [true, 'The name of the Post module to run']),
				OptString.new('OPTIONS', [false, 'Comma-separated list of options for the post module'])
			], self.class)
	end

	# Run Method for when run command is issued
	def run
		if datastore['MODULE'] =~ /^post/
			post_mod = datastore['MODULE'].gsub(/^post\//,"")
		else
			post_mod = datastore['MODULE']
		end
		sessions = datastore['SESSIONS']
		mod_opts = datastore['OPTIONS']

		print_status("Loading #{post_mod}")
		m= framework.post.create(post_mod)
		if sessions =~ /all/i
			session_list = m.compatible_sessions
		else
			session_list = sessions.split(",")
		end
		if session_list
			session_list.each do |s|
				if m.session_compatible?(s.to_i)
					print_status("Running Against #{s}")
					m.datastore['SESSION'] = s.to_i
					if mod_opts
						mod_opts.each do |o|
							opt_pair = o.split("=",2)
							print_status("\tSetting Option #{opt_pair[0]} to #{opt_pair[1]}")
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

