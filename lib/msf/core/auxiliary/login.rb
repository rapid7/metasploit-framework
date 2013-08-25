# -*- coding: binary -*-

module Msf

###
#
# This module exposes methods that may be useful to exploits that deal with
# servers that require authentication via /bin/login
#
###
module Auxiliary::Login

	NULL = "\000"
	CR   = "\r"
	LF   = "\n"
	EOL  = CR + LF

	#
	# Creates an instance of a login negoation module.
	#
	def initialize(info = {})
		super

		# Appended to by each read and gets reset after each send.  Doing it
		# this way lets us deal with partial reads in the middle of expect
		# strings, e.g., the first recv returns "Pa" and the second returns
		# "ssword: "
		@recvd = ''
		@trace = ''

		#
		# Some of these regexes borrowed from NeXpose, others added from datasets
		#
		@login_regex = /(?:log[io]n( name|)|user(name|id|))\s*\:/i
		@password_regex = /(?:password|passwd)\s*\:/i
		@false_failure_regex = /(?:(^\s*last)\ login *\:|allows only\ .*\ Telnet\ Client\ License)/i
		@failure_regex = /(?:
				Incorrect | Unknown  | Fail      | Invalid  |
				Login     | Password | Passwd    | Username |
				Unable    | Error    | Denied    | Reject   |
				Refuse    | Close    | Closing   | %\ Bad   |
				Sorry     |
				Not\ on\ system\ console |
				Enter\ username\ and\ password |
				Auto\ Apply\ On |
				YOU\ LOGGED\ IN\ USING\ ALL\ UPPERCASE\ CHARACTERS|
				\n\*$ |
				(Login ?|User ?)(name|): |
				^\s*\<[a-f0-9]+\>\s*$ |
				^\s*220.*FTP|
				not\ allowed\ to\ log\ in
			)/mix

		@waiting_regex = /(?:
			.*please\ wait.* |
			.*one\ minute.*
		)/mix

		@busy_regex = /(?:
			Another\ telnet\ session\ is\ in\ progress | Disconnecting\.\.\.
		)/mix

		@success_regex = /(?:
				list\ of\ built-in     |
				sh.*[\#\$]\s*$         |
				\[\/\]\s*$             |
				or\ the\ MENU\ system  |
				Password\ is\ not\ set |
				logging\ in\ as\ visitor |
				Login\ successful
			)/mix
	end

	#
	# Appends to the @recvd buffer which is used to tell us whether we're at a
	# login prompt, a password prompt, or a working shell.
	#
	def recv(fd=self.sock, timeout=10)

		data = ''

		begin
			data = fd.get_once(-1, timeout)
			return nil if not data or data.length == 0

			# combine EOL into "\n"
			data.gsub!(/#{EOL}/no, "\n")

			@trace << data
			@recvd << data
			fd.flush

		rescue ::EOFError, ::Errno::EPIPE
		end

		data
	end

	def login_prompt?
		return true if @recvd =~ @login_regex
		return false
	end

	def command_echo?(cmd)
		recvn = @recvd.gsub(/^(\s*#{cmd}\r?\n\s*|\s*\*+\s*)/, '')
		if(recvn != @recvd)
			@recvd = recvn
			return true
		end
		false
	end

	def waiting_message?
		recvn = @recvd.gsub(@waiting_regex, '')
		if(recvn != @recvd)
			@recvd = recvn.strip
			return true
		end
		false
	end

	def busy_message?
		recvn = @recvd.gsub(@busy_regex, '')
		if(recvn != @recvd)
			@recvd = recvn.strip
			return true
		end
		false
	end

	def password_prompt?
		return true if(@recvd =~ @password_regex)
		if datastore['USERNAME']
			return true if( !(datastore['USERNAME'].empty?) and @recvd =~ /#{datastore['USERNAME']}'s/)
		end
		return false
	end

	def login_failed?
		# Naively, failure means matching the failure regex.
		#
		# However, this leads to problems with false positives in the case of
		# "login:" because unix systems commonly show "Last login: Sat Jan  3
		# 20:22:52" upon successful login, so check against a false-positive
		# regex, also.
		#

		# Empty strings should not count
		if @recvd.strip.length == 0
			return true
		end

		# If we have not seen a newline, this is likely an echo'd prompt
		if ! @recvd.index("\n")
			return true
		end

		# We do have a set of highly-accurate success patterns
		if (@recvd =~ @success_regex)
			return false
		end

		if @recvd =~ @failure_regex
			if @recvd !~ @false_failure_regex
				return true
			end
		end
		return false
	end

	def login_succeeded?
		# Much easier to test for failure than success because a few key words
		# mean failure whereas all kinds of crap is used for success, much of
		# which also shows up in failure messages.
		return (not login_failed?)
	end

	#
	# This method logs in as the supplied user by transmitting the username
	#
	def send_user(user, nsock = self.sock)
		got_prompt = wait_for(@login_regex)
		if not got_prompt
			print_error("#{rhost} - Something is wrong, didn't get a login prompt")
		end
		return send_recv("#{user}\r\n")
	end

	#
	# This method completes user authentication by sending the supplied password
	#
	def send_pass(pass, nsock = self.sock)
		got_prompt = wait_for(@password_regex)
		if not got_prompt
			print_error("#{rhost} - Something is wrong, didn't get a password prompt")
		end
		return send_recv("#{pass}\r\n")
	end

	def send_recv(msg, nsock = self.sock)
		raw_send(msg, nsock)
		recv_all(nsock)
		return @recvd
	end

	def recv_all(nsock = self.sock, timeout = 10)
		# Make sure we read something in
		wait_for(/./)
	end

	#
	# This method transmits a telnet command and does not wait for a response
	#
	# Resets the @recvd buffer
	#
	def raw_send(cmd, nsock = self.sock)
		@recvd = ''
		@trace << cmd
		nsock.put(cmd)
	end

	#
	# Wait for the supplied string (or Regexp) to show up on the socket, or a
	# timeout
	#
	def wait_for(expect, nsock = self.sock)
		if expect.kind_of? Regexp
			regx = expect
		else
			regx = /#{Regexp.quote(expect)}/i
		end
		return true if @recvd =~ regx

		resp = ''
		while (resp and not @recvd =~ regx)
			resp = recv(nsock)
		end

		return (@recvd =~ regx)
	end

end

end
