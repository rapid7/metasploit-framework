##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

# The most useful and interesting feature of this module is the way the 
# loot file gets appended to, rather than rewritten. Might be use for
# this technique in other modules that gather loot.

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'DuckDuckGo Password Hash Search',
			'Description'    => %q{
				This module scrapes the DuckDuckGo search engine for appearances of the given hash.
				When a hash is mentioned on the Internet, it is usually accompanied by the plaintext
				version of the password. Good news for the attacker, bad news for the user.

				Note that this module almost certainly violates the Terms of Service of DuckDuckGo,
				which is a shame, and relegates this to a proof of concept trick until a combination
				of search engine, TOS, and a useful API surfaces.
			},
			'Author'         => [ 'todb' ],
			'References'     =>
				[
					[ 'URL', 'http://duckduckgo.com/' ] # I heart DDG and feel bad for abusing them :/
				]
		))

		register_options(
			[
				OptString.new('HASH', [ true, "The password hash to search for", "b963c57010f218edc2cc3c229b5e4d0f"]),
				OptBool.new('SSL', [ false, "Use SSL for hash searches", true]) # Just bringing this to the main opts list.
			], self.class)

		deregister_options('RHOST', 'RPORT', 'VHOST', 'Proxies')
	end

	def cleanup
		datastore['RHOST'] = @old_rhost
		datastore['RPORT'] = @old_rport
	end

	# Save the original rhost/rport in case the user was exploiting something else
	def save_rhost
		@old_rhost = datastore['RHOST']
		@old_rport = datastore['RPORT']
	end

	def pw_hash
		datastore['HASH'].to_s
	end

	def run
		save_rhost()

		# Need to set this for send_request_cgi()
		datastore['RHOST'] = "duckduckgo.com"
		datastore['RPORT'] = datastore['SSL'] ? 443 : 80

		loot = ""
		uri = "/html/"

		res = send_request_cgi({
			'method'   => 'GET',
			'uri'      => "/html/",
			'vars_get' => {"q" => pw_hash}
		}, 25)

		if res == nil or res.body == nil
			print_error("No response from DuckDuckGo.")
			return
		end

		ddg_res = find_ddg_response(res.body)
		if ddg_res
			print_good("DuckDuckGo's first listing for '#{pw_hash}' is at #{ddg_res}")
			report_hash_found(ddg_res)
		else
			print_status("No results for #{datastore['HASH']} were found via DuckDuckGo.")
			return
		end

	end

	# Instead of one loot file at a time, it's nicer to just append.
	def report_hash_found(url)
		return unless framework.db.active
		loot_header = "Hash,URL"
		loot_line = "\"#{pw_hash}\",\"#{url}\"\n"
		existing_loot = framework.db.loots.find_by_ltype("internet.hashes")
		if existing_loot
			append_to_loot(existing_loot,loot_line,url)
		else
			loot_file = [loot_header,loot_line].join("\n")
			p = store_loot("internet.hashes","text/plain",nil,loot_file,"internet_hashes.csv","Internet-Searchable Hashes") 
			print_status("Saved hash and URL to #{p}")
		end
	end

	def append_to_loot(existing_loot,loot_line,url)
		dupe_hash = false
		p = existing_loot.path
		fh = ::File.open(p, "r+b")
		fh.each_line do |line|
			if line == loot_line
				dupe_hash = true
				break
			end
		end
		if dupe_hash
			print_status "Discarding duplicate hash '#{pw_hash}' found in #{existing_loot.path}"
			fh.close
			return
		end
		# fh.seek(fh.stat.size)
		fh.write loot_line
		fh.close
		existing_loot.updated_at = Time.now.utc
		existing_loot.save
		print_status("Appended hash and URL to #{p}")
	end

	def find_ddg_response(html)
		first_result = html.match(/<div[^>]+web\-result.*?This is the visible part/m)[0]
		return nil unless first_result
		url = first_result.match(/href=\x22(http.*)\x22/)[1] rescue nil
		return url
	end

end
