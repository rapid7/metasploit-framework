module Msf

###
#
# This module provides methods for brute forcing authentication
#
###

module Auxiliary::AuthBrute

def initialize(info = {})
	super

	register_options([
			OptPath.new('USERNAMES_FILE', [ false, "File containing usernames, one per line" ]),
			OptPath.new('PASSWORDS_FILE', [ false, "File containing passwords, one per line" ]),
			OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line" ])
		], Auxiliary::AuthBrute)

	@user = nil
	@pass = nil

end


def each_user_pass(&block)
	#$stdout.puts("Running through users and passwords")
	if framework.db.active
		#$stdout.puts("Using db auth info")
		framework.db.get_auth_info.each { |auth_info|
			next if not auth_info.kind_of? Hash
			next if not auth_info.has_key? :user
			next if not auth_info.has_key? :pass
			block.call(auth_info[:user], auth_info[:pass])
		}
	end

	#$stdout.puts("Getting userpass")
	while next_userpass
		#$stdout.puts("calling block with #{@user} : #{@pass}")
		block.call(@user, @pass)
	end

	while next_user
		#$stdout.puts("Getting user")
		while next_pass
			#$stdout.puts("calling block with #{@user} : #{@pass}")
			ret = block.call(@user, @pass)
			case ret
			when :next_user; break
			end
		end
	end
end

protected
def next_user
	return nil if not datastore["USERNAMES_FILE"]
	@user_fd ||= File.open(datastore["USERNAMES_FILE"], "r")
	return nil if @user_fd.eof?
	@user = @user_fd.readline
	true
end
def next_pass
	return nil if not datastore["PASSWORDS_FILE"]
	@user_fd ||= File.open(datastore["PASSWORDS_FILE"], "r")
	return nil if @pass_fd.eof?
	@pass = @pass_fd.readline
	true
end
def next_userpass
	return if not datastore["USERPASS_FILE"]
	@userpass_fd ||= File.open(datastore["USERPASS_FILE"], "r")
	return nil if @userpass_fd.eof?
	line = @userpass_fd.readline
	@user, @pass = line.split(/\s+/, 2)
	@pass = "" if @pass.nil?
	true
end


end
end

