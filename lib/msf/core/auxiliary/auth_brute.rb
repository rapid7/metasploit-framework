module Msf

###
#
# This module provides methods for brute forcing authentication
#
###

module Auxiliary::AuthBrute

	attr_accessor :credentials_tried, :credentials_good

def initialize(info = {})
	super

	register_options([
			OptPath.new('USER_FILE', [ false, "File containing usernames, one per line" ]),
			OptPath.new('PASS_FILE', [ false, "File containing passwords, one per line" ]),
			OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line" ]),
			OptInt.new('BRUTEFORCE_SPEED', [ true, "How fast to bruteforce, from 0 to 5", 5]),
			OptBool.new('VERBOSE', [ true, "Whether to print output for all attempts", true]),
		], Auxiliary::AuthBrute)

	@user = nil
	@pass = nil
	@credentials_tried = {}
	@credentials_good = {}

end

#
# Calls the given block with usernames and passwords generated in the following way, in order:
#	* the module's next_user_pass(), if any
#	* contents of USERPASS_FILE, if any
#	* the module's next_user() combined with next_pass() and the contents of PASS_FILE
#	* contents of USER_FILE combined with the module's next_pass() and the contents of PASS_FILE
#
# After any invocation, the block may return
#	:next_user
#		to indicate that the current user needs no further processing and
#		brute forcing should continue with the next username or
#	:done
#		to indicate that brute forcing should end completely.
#
# Generator methods (next_pass, and next_user_pass) must reset their state
# whenever they reach the end.
#
def each_user_pass(&block)
	# First, loop through sets of user/pass combinations
	[ "next_user_pass", "_next_user_pass" ].each { |userpass_meth|
		next if not self.respond_to?(userpass_meth)
		@state = {}
		@state[:status] = nil
		while (upass = self.send(userpass_meth, @state))
			@state[:status] = block.call(upass[0], upass[1])
			case @state[:status]
			# Let the generate method deal with :next_user
			when :done; return
			end
		end
	}

	# Then combinatorically examine all of the separate usernames and passwords
	each_user { |user|
		each_pass(user) { |pass|
			status = block.call(user, pass)
			case status
			when :next_user; break
			when :done; return
			end
		}
	}

end

def each_user(&block)
	state = {}
	if self.respond_to? "next_user"
		while user = next_user(state)
			yield user
		end
	end
	while user = _next_user(state)
		yield user
	end
end

def each_pass(user=nil, &block)
	state = {:user => user}
	if self.respond_to? "next_pass"
		while pass = next_pass(state)
			yield pass
		end
	end
	while pass = _next_pass(state)
		yield pass
	end
end

def userpass_sleep_interval
	sleep_time = case datastore['BRUTEFORCE_SPEED'].to_i
		when 0;
			60 * 5
		when 1;
			15
		when 2;
			1
		when 3;
			0.5
		when 4;
			0.1
		else;
			0
	end
	select(nil,nil,nil,sleep_time) unless sleep_time == 0
end

def vprint_status(msg='')
	return if not datastore['VERBOSE']
	print_status(msg)
end

def vprint_error(msg='')
	return if not datastore['VERBOSE']
	print_error(msg)
end

def vprint_good(msg='')
	return if not datastore['VERBOSE']
	print_good(msg)
end

protected
#
# These methods all close their files after reaching EOF so that modifications
# to the username/password lists during a run will be reflected in the next
# run.
#

def _next_user(state)
	if not state[:used_datastore] and datastore['USERNAME']
		state[:used_datastore] = true
		return datastore['USERNAME']
	end
	return nil if not datastore["USER_FILE"]

	state[:user_fd] ||= File.open(datastore["USER_FILE"], "r")
	if state[:user_fd].eof?
		state[:user_fd].close
		state[:user_fd] = nil
		return nil
	end
	state[:user] = state[:user_fd].readline.strip
	return state[:user]
end
def _next_pass(state)
	if not state[:used_datastore] and datastore['PASSWORD']
		state[:used_datastore] = true
		return datastore['PASSWORD']
	end
	return nil if not datastore["PASS_FILE"]
	state[:pass_fd] ||= File.open(datastore["PASS_FILE"], "r")
	if state[:pass_fd].eof?
		state[:pass_fd].close
		state[:pass_fd] = nil
		return nil
	end
	state[:pass] = state[:pass_fd].readline.strip
	return state[:pass]
end
def _next_user_pass(state)
	return if not datastore["USERPASS_FILE"]
	# Reopen the file each time so that we pick up any changes
	state[:userpass_fd] ||= File.open(datastore["USERPASS_FILE"], "r")
	if state[:userpass_fd].eof?
		state[:userpass_fd].close
		state[:userpass_fd] = nil
		return nil
	end
	line = state[:userpass_fd].readline
	state[:user], state[:pass] = line.split(/\s+/, 2)
	state[:pass] = "" if state[:pass].nil?
	state[:user].strip!
	state[:pass].strip!
	return [ state[:user], state[:pass] ]
end


end
end

