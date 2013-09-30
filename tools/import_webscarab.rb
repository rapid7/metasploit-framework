#!/usr/bin/env ruby
#
# $Id$
# $Revision$
#

# Script which allows to import OWASP WebScarab sessions
# (http://www.owasp.org/index.php/Category:OWASP_WebScarab_Project)
# into the metasploit/WMAP database.
# By spinbad <spinbad.security () googlemail ! com>

require 'resolv'
require 'sqlite3'

puts "--- WMAP WebScarab Session Importer ---------------------------------------------"
puts

if ARGV.length < 2
  $stderr.puts("Usage: #{File.basename($0)} wescarabdirectory sqlite3database [target] [startrequest]")
  $stderr.puts
  $stderr.puts("webscarabdirectory\tThe directory where you stored the webscarab session")
  $stderr.puts("sqlite3database\t\tThe name of the database file")
  $stderr.puts("target\t\t\tThe target (host or domain) you want to add to the database")
  $stderr.puts("startrequest\tThe request to start with...")
  $stderr.puts
  $stderr.puts("Examples:")
  $stderr.puts("#{File.basename($0)} /tmp/savedsession example.db")
  $stderr.puts("#{File.basename($0)} /tmp/savedsession example.db www.example.com")
  $stderr.puts("#{File.basename($0)} /tmp/savedsession example.db example.com")
  $stderr.puts("#{File.basename($0)} /tmp/savedsession example.db www.example.com 21")
  exit
end

ws_directory  = ARGV.shift
db_file   	     = ARGV.shift
target	     = ARGV.shift || nil
start_id	     = ARGV.shift.to_i || 1

# check if we have what we need...
if File.exists?(ws_directory+ File::SEPARATOR) == false then
  $stderr.puts("ERROR: Can't find webscarab directory #{ws_directory}.")
  exit
end

if File.file?(db_file) == false then
  $stderr.puts("ERROR: Can't find sqlite3 database file #{db_file}.")
  exit
end

# Prepare the database
puts("Opening database file: #{db_file}")
database = SQLite3::Database.new(db_file)

# Prepare the insert statement...
insert_statement = database.prepare("INSERT INTO requests(host,port,ssl,meth,path,headers,query,body,respcode,resphead,response,created)" +
  " VALUES(:host,:port,:ssl,:meth,:path,:headers,:query,:body,:respcode,:resphead,:response,:created)");

# target hash -> Resolving dns names is soooo slow, I don't know why. So we use the
# following hash as a "micro hosts", so we don't have to call getaddress each time...
target_ips = {}

# Try to open the conversationlog file
File.open("#{ws_directory+File::SEPARATOR}conversationlog", "rb") do |log|

  # regulare expressions to extract the stuff that we really need
  # i know that the url stuff can be handeled in one request but
  # i am toooo lazy...
  regex_conversation = /^### Conversation : (\d+)/
  regex_datetime	= /^WHEN: (\d+)/
  regex_method      	= /^METHOD: (\S+)/
  regex_status     	= /^STATUS: (\d\d\d)/
  regex_url		 	= /^URL: (http|https)?:\/\/(\S+):(\d+)\/([^\?]*)\?*(\S*)/

  while line = log.gets
    if line =~ regex_conversation then
      conversation_id = regex_conversation.match(line)[1]
      next if conversation_id.to_i < start_id

      # we don't care about scripts, commets
      while (line =~ regex_datetime) == nil
        line = log.gets
      end

      # Add a dot to the timestring so we can convert it more easily
      date_time = regex_datetime.match(line)[1]
      date_time = Time.at(date_time.insert(-4, '.').to_f)

      method    = regex_method.match(log.gets)[1]

      # we don't care about COOKIES
      while (line =~ regex_status) == nil
        line = log.gets
      end
      status        = regex_status.match(line)[1]

      url_matcher = regex_url.match(log.gets)

      puts "Processing (#{conversation_id}): #{url_matcher[0]}"

      ssl		    = url_matcher[1] == "https"
      host_name  = url_matcher[2]
      port             = url_matcher[3]
      path	   	    = url_matcher[4].chomp
      query	    = url_matcher[5]

      if host_name.match("#{target}$").nil? == true	 	then
        puts("Not the selected target, skipping...")
        next
      end

      if(target_ips.has_key?(host_name)) then
        host = target_ips[host_name]
      else
        ip = Resolv.getaddress(host_name)
        target_ips[host_name] = ip
        host = ip
      end

      # set the parameters in the insert query
      insert_statement.bind_param("host", host)
      insert_statement.bind_param("port", port)
      insert_statement.bind_param("ssl", ssl)
      insert_statement.bind_param("meth", method)
      insert_statement.bind_param("path", path)
      insert_statement.bind_param("query", query)
      insert_statement.bind_param("respcode", status)
      insert_statement.bind_param("created", date_time)
      insert_statement.bind_param("respcode", status)

      #Open the files with the requests and the responses...
      request_filename = "#{ws_directory+File::SEPARATOR}conversations#{File::SEPARATOR+conversation_id}-request"
      puts("Reading #{request_filename}")
      request_file = File.open(request_filename, "rb")

      # Analyse the request
      request_header = ""
      request_file.gets # we don't need the return code...
      while(request_line = request_file.gets)  do
          request_header += request_line
          break if request_line == "\r\n"
      end


      request_body = ""
      while(request_line = request_file.gets) do
        request_body += request_line
      end

      insert_statement.bind_param("headers", request_header)
      insert_statement.bind_param("body", request_body)

      request_file.close()

      response_filename = "#{ws_directory+File::SEPARATOR}conversations#{File::SEPARATOR+conversation_id}-response"
      puts("Reading #{response_filename}")
      response_file = File.open("#{ws_directory+File::SEPARATOR}conversations#{File::SEPARATOR+conversation_id}-response", "rb")

      # scip the first line
      response_file.gets

      # Analyse the response
      response_header = ""
      while(response_line = response_file.gets) do
        response_header += response_line
        break if response_line == "\r\n"
      end

      response_body = response_file.read

      insert_statement.bind_param("resphead", response_header)
      insert_statement.bind_param("response", response_body)

      response_file.close()

      insert_statement.execute()
    end
  end
end
