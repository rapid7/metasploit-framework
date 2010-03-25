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
	OptPath.new('USER_FILE', [ false, "File containing usernames, one per line" ]),
	OptPath.new('PASS_FILE', [ false, "File containing passwords, one per line" ]),
	OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line" ]),
	OptInt.new('BRUTEFORCE_SPEED', [ true, "How fast to bruteforce, from 0 to 5", 5]),
	OptBool.new('VERBOSE', [ true, "Whether to print output for all attempts", true]),
	OptBool.new('BLANK_PASSWORDS', [ true, "Try blank passwords for all users", true])
	], Auxiliary::AuthBrute)

end

# Checks all three files for usernames and passwords, and combines them into
# one credential list to apply against the supplied block. The block (usually
# something like do_login(user,pass) ) is responsible for actually recording
# success and failure in its own way; each_user_pass() will only respond to
# a return value of :done (which will signal to end all processing) and
# to :next_user (which will cause that username to be skipped for subsequent
# password guesses). Other return values won't affect the processing of the
# list.
def each_user_pass(&block)
	# Class variables to track credential use (for threading)
	@@credentials_tried = {}
	@@credentials_skipped = {}
	credentials = extract_word_pair(datastore['USERPASS_FILE'])
	users       = extract_words(datastore['USER_FILE'])
	passwords   = extract_words(datastore['PASS_FILE'])
	if datastore['BLANK_PASSWORDS']
		credentials = gen_blank_passwords(users,credentials) + credentials
	end
	credentials.concat(combine_users_and_passwords(users,passwords))
	credentials = just_uniq_passwords(credentials) if @strip_usernames
	credentials.each do |u,p|
		fq_user = "%s:%s:%s" % [datastore['RHOST'], datastore['RPORT'], u]
		userpass_sleep_interval unless @@credentials_tried.empty?
		next if @@credentials_skipped[fq_user]
		next if @@credentials_tried[fq_user] == p
		ret = block.call(u,p)
		case ret
		when :abort
		break
		when :next_user
			@@credentials_skipped[fq_user] = p
		end
	@@credentials_tried[fq_user] = p
	end
	return
end

def just_uniq_passwords(credentials)
	new_creds = credentials.map{|x| x[0] = ""; x}
	credentials.uniq
end

def gen_blank_passwords(user_array,cred_array)
	blank_passwords = []
	unless user_array.empty?
		blank_passwords.concat(user_array.map {|u| [u,""]})
	end
	unless cred_array.empty?
		cred_array.each {|u,p| blank_passwords << [u,""]}
	end
	return blank_passwords
end

def combine_users_and_passwords(user_array,pass_array)
	combined_array = []
	if (user_array + pass_array).empty?
		return []
	end
	if pass_array.empty?
		combined_array = user_array.map {|u| [u,""] }
	elsif user_array.empty?
		combined_array = pass_array.map {|p| ["",p] }
	else
		user_array.each do |u|
			pass_array.each do |p|
				combined_array << [u,p]
			end
		end
	end
	return combined_array
end

def extract_words(wordfile)
	return [] unless wordfile && File.readable?(wordfile)
	begin
		words = File.open(wordfile) {|f| f.read}
	rescue
		return
	end
	save_array = words.split(/\n/).map { |x| x.scan(/[\w]+/).first.to_s }
	return save_array
end

def extract_word_pair(wordfile)
	return [] unless wordfile && File.readable?(wordfile)
	creds = []
	begin
		upfile_contents = File.open(wordfile) {|f| f.read}
	rescue
		return []
	end
	upfile_contents.split(/\n/).each do |line|
		user,pass = line.split(/\s+/,2).map { |x| x.strip }
		creds << [user.to_s, pass.to_s]
	end
	return creds
end

def userpass_sleep_interval
	sleep_time = case datastore['BRUTEFORCE_SPEED'].to_i
	when 0; 60 * 5
	when 1; 15
	when 2; 1
	when 3; 0.5
	when 4; 0.1
	else; 0
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

end
end

