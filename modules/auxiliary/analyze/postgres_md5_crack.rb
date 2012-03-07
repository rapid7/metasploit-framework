##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
#
##


require 'msf/core'
require 'digest/md5'

class Metasploit3 < Msf::Auxiliary

	#Included to grab the john.pot and use some utiltiy functions
	include Msf::Auxiliary::JohnTheRipper

	def initialize
		super(
			'Name'           => 'Postgres SQL md5 Password Cracker',
			'Version'        => '$Revision$',
			'Description'    => %Q{
					This module attempts to crack Postgres SQL md5 password hashes.
				It creates hashes based on information saved in the MSF Database
				such as hostnames, usernames, passwords, and database schema information.
				The user can also supply an additional external wordlist if they wish.
			},
			'Author'         => ['TheLightCosine <thelightcosine[at]gmail.com>'],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				OptPath.new('Wordlist', [false, 'The path to an optional Wordlist']),
				OptBool.new('Munge',[false, 'Munge the Wordlist (Slower)', false])
			])

		deregister_options('JOHN_BASE','JOHN_PATH')
	end

	def run

		print_status("Processing wordlist...")
		@seed= build_seed()

		print_status("Wordlist length: #{@seed.length}")

		myloots = myworkspace.loots.where('ltype=?', 'postgres.hashes')
		unless myloots.nil?
			myloots.each do |myloot|
				begin
					postgres_array = CSV.read(myloot.path).drop(1)
				rescue
					print_error("Unable to process #{myloot.path}")
				end
				postgres_array.each do |row|
					print_status("Attempting to crack hash: #{row[0]}:#{row[1]}")
					password = crack_hash(row[0],row[1])
					if password
						print_good("Username: #{row[0]} Pass: #{password}")
						report_auth_info(
							:host  => myloot.host.address,
							:port => myloot.service.port,
							:sname => 'postgres',
							:user => row[0],
							:pass => password
						)

					end
				end
			end
		end

	end

	def crack_hash(username,hash)

		@seed.each do |word|
			tmphash =  Digest::MD5.hexdigest("#{word}#{username}")
			if tmphash == hash
				return word
			end
		end

		return nil

	end


	def build_seed

		seed = []
		#Seed the wordlist with Database , Table, and Instance Names
		schemas = myworkspace.notes.where('ntype like ?', '%.schema%')
		unless schemas.nil? or schemas.empty?
			schemas.each do |anote|
				anote.data.each do |key,value|
					seed << key
					value.each{|a| seed << a}
				end
			end
		end

		instances = myworkspace.notes.where('ntype=?', 'mssql.instancename')
		unless instances.nil? or instances.empty?
			instances.each do |anote|
				seed << anote.data['InstanceName']
			end
		end

		# Seed the wordlist with usernames, passwords, and hostnames

		myworkspace.hosts.find(:all).each {|o| seed << john_expand_word( o.name ) if o.name }
		myworkspace.creds.each do |o|
			seed << john_expand_word( o.user ) if o.user
			seed << john_expand_word( o.pass ) if (o.pass and o.ptype !~ /hash/)
		end

		# Grab any known passwords out of the john.pot file
		john_cracked_passwords.values {|v| seed << v }

		#Grab the default John Wordlist
		john = File.open(john_wordlist_path, "rb")
		john.each_line{|line| seed << line.chomp}

		if datastore['Wordlist']
			wordlist= File.open(datastore['Wordlist'], "rb")
			wordlist.each_line{|line| seed << line.chomp}
		end

		unless seed.empty?
			seed.flatten!
			seed.uniq!

			if datastore['Munge']
				mungedseed=[]
				seed.each do |word|
					munged = word.gsub(/[sS]/, "$").gsub(/[aA]/,"@").gsub(/[oO]/,"0")
					mungedseed << munged
					munged.gsub!(/[eE]/, "3")
					munged.gsub!(/[tT]/, "7")
					mungedseed << munged
				end
				seed << mungedseed
				seed.flatten!
				seed.uniq!
			end
		end

		return seed
	end

end
