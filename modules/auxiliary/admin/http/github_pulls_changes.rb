##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient

	def initialize
		super(
			'Name'           => 'Gighub pulls requests files changed summary',
			'Description'    => %q{
					This module uses the github api to summarize files changed
				by pull requests.
			},
			'References'     =>
				[
					['URL', 'http://developer.github.com/v3/pulls/#list-pull-requests']
				],
			'DisclosureDate' => 'Mar 11 2013',
			'Author'         => [ 'juan vazquez' ],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(443),
				Opt::RHOST('api.github.com'),
				OptString.new("TARGETURI", [true, 'The URI directory where basic auth is enabled', '/']),
				OptString.new("OWNER", [true, 'The Repo owner', 'rapid7']),
				OptString.new("REPO", [true, 'The Repo name', 'metasploit-framework']),
				OptString.new("USERNAME", [true, 'Github username', 'jvazquez-r7']),
				OptString.new("PASSWORD", [true, 'Github password',]),
				OptBool.new('SSL', [true, 'Use SSL', true])
			], self.class)
	end

	def get_files(id)
		res = send_request_cgi({
			'uri'       => normalize_uri(target_uri.path, "repos", @owner, @repo, "pulls", id, "files"),
			'method'    => 'GET',
			'authorization' => basic_auth(datastore['USERNAME'],datastore['PASSWORD'])
		})

		if res and res.code == 200
			if res.headers['X-RateLimit-Remaining'].to_i == 0
				print_error("Warning Rate Limit reached retrieving files for ##{id}")
				print_error("Your rate limit is #{res.headers['X-RateLimit-Limit']}")
			end
			files = JSON.parse(res.body)
			return files.map { |f| "#{f["filename"]} => #{f["status"]}" }
		else
			return nil
		end
	end

	def run

		@owner = datastore["OWNER"]
		@repo = datastore["REPO"]

		pulls = []

		page = 1

		begin
			res = send_request_cgi({
				'uri'       => normalize_uri(target_uri.path, "repos", @owner, @repo, "pulls"),
				'method'    => 'GET',
				'authorization' => basic_auth(datastore['USERNAME'],datastore['PASSWORD']),
				'vars_get'  => {
					'page' => "#{page}"
				}
			})

			if res and res.code == 200 and res.headers['X-RateLimit-Remaining'].to_i > 0
				p_pulls = JSON.parse(res.body)
				pulls << p_pulls
				pulls.flatten!
			else
				print_error("Error retrieving pulls requests")
				return
			end
			page = page + 1
		end while (res and res.code == 200 and not p_pulls.empty?)

		results_table = Rex::Ui::Text::Table.new(
			'Header'  => 'GitHub Pull Requests Summary',
			'Indent'  => 1,
			'Columns' => ['Pull #', 'Pull Title', '# Files', 'Modifications']
		)

		pulls.each {|p|
			if p["state"] == "open"
				files = get_files(p["number"])
				if files.nil?
					results_table << [p["number"], p["title"], "-", "-"]
					next
				end

				results_table << [p["number"], p["title"], files.length, files.join(", ")]
			end
		}

		print_line
		print_line(results_table.to_s)
	end
end
