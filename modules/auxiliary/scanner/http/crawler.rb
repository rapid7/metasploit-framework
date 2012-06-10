##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex/proto/http'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::HttpCrawler

	def initialize
		super(
			'Name'        => 'Web Site Crawler',
			'Version'     => '$Revision$',
			'Description' => 'Crawl a web site and store information about what was found',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)

	end

=begin
	# Prefer dynamic content over non-dynamic
	def focus_crawl(page)
		page.links
	end
=end

	#
	# The main callback from the crawler, redefines crawler_process_page() as
	# defined by Msf::Auxiliary::HttpCrawler
	#
	# Data we will report:
	# - The path of any URL found by the crawler (web.uri, :path => page.path)
	# - The occurence of any form (web.form :path, :type (get|post|path_info), :params)
	#
	def crawler_process_page(t, page, cnt)
		msg = "[#{"%.5d" % cnt}/#{"%.5d" % max_page_count}]    #{page.code || "ERR"} - #{t[:vhost]} - #{page.url}"
		case page.code
			when 301,302
				if page.headers and page.headers["location"]
					print_status(msg + " -> " + page.headers["location"].to_s)
				else
					print_status(msg)
				end
			when 500...599
				# XXX: Log the fact that we hit an error page
				print_good(msg)
			when 401,403
				print_good(msg)
			when 200
				print_status(msg)
			when 404
				print_error(msg)
			else
				print_error(msg)
		end

		#
		# Process the web page
		#

		info = {
			:web_site => t[:site],
			:path     => page.url.path,
			:query    => page.url.query,
			:code     => page.code,
			:body     => page.body,
			:headers  => page.headers
		}

		if page.headers['content-type']
			info[:ctype] = page.headers['content-type']
		end

		if page.headers['set-cookie']
			info[:cookie] = page.headers['set-cookie']
		end

		if page.headers['authorization']
			info[:auth] = page.headers['authorization']
		end

		if page.headers['location']
			info[:location] = page.headers['location']
		end

		if page.headers['last-modified']
			info[:mtime] = page.headers['last-modified']
		end

		# Report the web page to the database
		report_web_page(info)

		# Only process interesting response codes
		return if not [302, 301, 200, 500, 401, 403, 404].include?(page.code)

		#
		# Skip certain types of forms right off the bat
		#

		# Apache multiview directories
		return if page.url.query =~ /^C=[A-Z];O=/ # Apache

		# Scrub out the jsessionid appends
		page.url.path = page.url.path.sub(/;jsessionid=[a-zA-Z0-9]+/, '')

		#
		# Continue processing forms
		#
		forms = []
		form_template = { :web_site => t[:site] }
		form  = {}.merge(form_template)

		# This page has a query parameter we can test with GET parameters
		# ex: /test.php?a=b&c=d
		if page.url.query and not page.url.query.empty?
			form[:method] = 'GET'
			form[:path]   = page.url.path
			vars = page.url.query.split('&').map{|x| x.split("=", 2) }
			form[:params] = vars
		end

		# This is a REST-ish application with numeric parameters
		# ex: /customers/343
		if not form[:path] and page.url.path.to_s =~ /(.*)\/(\d+)$/
			path_base = $1
			path_info = $2
			form[:method] = 'PATH'
			form[:path]   = path_base
			form[:params] = [['PATH', path_info]]
			form[:query]  = page.url.query.to_s
		end

		# This is an application that uses PATH_INFO for parameters:
		# ex:  /index.php/Main_Page/Article01
		if not form[:path] and page.url.path.to_s =~ /(.*\/[a-z0-9A-Z]{3,256}\.[a-z0-9A-Z]{2,8})(\/.*)/
			path_base = $1
			path_info = $2
			form[:method] = 'PATH'
			form[:path]   = path_base
			form[:params] = [['PATH', path_info]]
			form[:query]  = page.url.query.to_s
		end

		# Done processing URI-based forms
		forms << form

		if page.doc
			page.doc.css("form").each do |f|

				target = page.url

				if f['action'] and not f['action'].strip.empty?
					action = f['action']

					# Prepend relative URLs with the current directory
					if action[0,1] != "/" and action !~ /\:\/\//
						# Extract the base href first
						base = target.path.gsub(/(.*\/)[^\/]+$/, "\\1")
						page.doc.css("base").each do |bref|
							if bref['href']
								base = bref['href']
							end
						end
						action = (base + "/").sub(/\/\/$/, '/') + action
					end

					target = page.to_absolute(URI( action )) rescue next

					if not page.in_domain?(target)
						# Replace 127.0.0.1 and non-qualified hostnames with our page.host
						# ex: http://localhost/url OR http://www01/url
						target_uri = URI(target.to_s)
						if (target_uri.host.index(".").nil? or target_uri.host == "127.0.0.1")
							target_uri.host = page.url.host
							target = target_uri
						else
							next
						end
					end
				end

				form = {}.merge!(form_template)
				form[:method] = (f['method'] || 'GET').upcase
				form[:query]  = target.query.to_s if form[:method] != "GET"
				form[:path]   = target.path
				form[:params] = []
				f.css('input', 'textarea').each do |inp|
					form[:params] << [inp['name'].to_s, inp['value'] || inp.content || '', { :type => inp['type'].to_s }]
				end

				# XXX: handle SELECT elements

				forms << form
			end
		end

		# Report each of the discovered forms
		forms.each do |form|
			next if not form[:method]
			print_status((" " * 24) + "FORM: #{form[:method]} #{form[:path]}")
			report_web_form(form)
			self.form_count += 1
		end
	end
end
