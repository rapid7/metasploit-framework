# include this file to gain a buch of methods helpful to writing more elaborate resource files
# like when using a resource file for a demo or automation etc
# $Author: kernelsmith

	#`'~.~'^\_/^*-..-*`'~.~'^\_/^*-..-*`'~.~'^\_/^*-..-*`'~.~'^\_/^*-.
	#                                                                 \
	# Helper methods for demo'ing and general resource visual coolness >
	#                                                                 /
	#_.~*~._/^\_,-''-._.~*~._/^\_,-''-._.~*~._/^\_,-''-._.~*~._/^\_,-'
	
	#
	# Method for simple pause, press enter to continue 
	#
	def rc_pause(tout = 0, verbose = true)
		require 'timeout'
		print_good('PAUSED - enter to continue') if verbose
		#gets
		begin
			Timeout::timeout(tout) {gets()}
		rescue Timeout::Error
			print_status "The pause timed out" if verbose
		end
		print_good('Continuing...') if verbose
	end
	
	#`'~.~'^\_/^*-..-*`'~.~'^\_/^*-..-*`'~.~'^\_/^*-..-*`'~.~'^\_/^*-.
	#                                                                 \
	# Helper methods for running modules more easily                   >
	#                                                                 /
	#_.~*~._/^\_,-''-._.~*~._/^\_,-''-._.~*~._/^\_,-''-._.~*~._/^\_,-'
	
	#
	# this method helps automatically set LHOST
	#
	
	# NOTE, if you don't want LHOST to be your "default route" interface, you should call this
	#       with target net changed to something in the network attached to the interface you do want

	# target_net is important if you have multiple interfaces and you want a specific one.
	# The interface LHOST will be set to is chosen by what interface is used to route to target_net
	# whether or not target_net exists is irrelevant, but if it doesn't LHOST will become
	# whatever interface is connected to the default route, in that case target_net could be any
	# publicly routable IP, or just nil
	# if you are using virtual interfaces etc, you might want target_net to be one of your vmnets
	# like if your "host-only" network is 192.168.170.1/24 you could: rc_auto_lhost("192.168.170.1")
	# and no matter what your ip actually is on that network, this will figure it out
	
	def rc_auto_lhost(target_network="5.5.5.5")
		# in case someone accidentally passes in a cidr range:
		target_network = target_network.split('/').first if target_network =~ /\//
		# in case someone passes in a network range, which most likely won't work well but...
		# and this just picks the first ip in the range provided
		if target_network =~ /-/
			tmp = []
			target_octets = target_network.split('.')
			target_octets.each do |octet|
				tmp << octet.split('-').first
			end
			target_network = tmp.join('.')
		end
		print_status "Using target network #{target_network}"
		my_interface = Rex::Socket.source_address(target_network)
		run_single("set LHOST #{my_interface}")
		run_single("setg LHOST #{my_interface}")
	end
	
	#
	# this method just sets up a persistent multi/handler on the given port
	#
	def rc_auto_handler(rc_port=4444)
		run_single("use multi/handler")
		run_single("set PAYLOAD windows/meterpreter/reverse_tcp")
		run_single("set LPORT #{rc_port}")
		run_single("set ExitOnSession false")
		run_single("exploit -j -z")
	end
	
	#
	# this method helps you perform a clear screen, esp when other methods of doing so fail
	#

	# You might have to modify this script for your OS & shell, to do so
	# do the following
	# run %x{clear} in irb, put the resulting string below
	# If you're running msf in Cygwin, in Windows, make sure to run
	# the irb command in Cygwin (untested)
	# If you are running MSF in Windows (is that even possible these days?), do
	# run %x{cls} in irb and put the resulting string below
	# Tested on BT5r1, with BASH
	
	def rc_clear
		rc_clear_string = "\e[H\e[2J"
		$stdout.print rc_clear_string
	end
	
	#
	# Method to let us do variable timing delays
	#
	def rc_var_delay(dmin=20,dmax=300)
		wtime = rand(dmax-dmin) + dmin
		print_good "Delaying for #{wtime} seconds"
		while wtime > 0
			printf("\r%d",wtime)
			select(nil, nil, nil, 1)
			wtime -= 1
		end
		print_line
		print_good "Continuing..."
	end
	
	#
	# Method for a simple delay
	#
	def rc_delay(wtime=5,verbose=true)
		print_good "Delaying for #{wtime} seconds" if verbose
		while wtime > 0
			printf("\r%d",wtime) if verbose
			select(nil, nil, nil, 1)
			wtime -= 1
		end
		print_line
		print_good "Continuing..." if verbose
	end



