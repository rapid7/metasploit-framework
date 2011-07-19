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

class Metasploit3 < Msf::Auxiliary
	include Msf::Ui::Console
	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Multi Manage Execute Meterpreter Console Command Resource File',
				'Description'   => %q{Execute Meterpreter Console Commands in resourcefileagainst
									specified sessions.},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision$'
			))
		register_options(
			[
				OptString.new('RESOURCE', [true, 'Resource file with space separate values <session> <command>, per line.', nil])
			], self.class)
	end

	# Run Method for when run command is issued
	def run

		entries = []
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
			print_error("Resourse file does not exist.")
		end

		entries.each do |entrie|
			session_parm,command = entrie.split(" ", 2)
			current_sessions = framework.sessions.keys.sort
			if session_parm =~ /all/i
				sessions = current_sessions
			else
				sessions = session_parm.split(",")
			end
			
			sessions.each do |s|
				# Check if session is in the current session list.
				next if not current_sessions.include?(s.to_i)

				# Get session object
				session = framework.sessions.get(s.to_i)

				# Check if session is meterpreter and run command.
				if (session.type == "meterpreter")
					print_good("Running command #{command} against sessions #{s}")
					session.console.run_single(command)
				else
					print_error("Sessions #{s} is not a Meterpreter Sessions!")
				end
			end
		end
	end

	
end