#
# This plugin provides integration with beSECURE. Written by Noam Rathaus.
#
# Distributed under MIT license:
# http://www.opensource.org/licenses/mit-license.php
#
# Version 10.5.17

require "base64"
require "zlib"
require 'tempfile'
require 'pathname'

module Msf
class Plugin::BeSECURE < Msf::Plugin
  class BeSECURECommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    def name
      "beSECURE"
    end

    def commands
      {
        'besecure_help' => "Displays help",
        'besecure_version' => "Display the version of the beSECURE server",
        'besecure_apikey' => "Set the beSECURE API Key",
        'besecure_hostname' => "Set the beSECURE Hostname",
        'besecure_debug' => "Enable/Disable debugging",
        'besecure_ssl_verify' => "Enable/Disable SSL verification",

        'besecure_report_list' => "Display list of reports",

        'besecure_report_download' => "Save a report to disk",
        'besecure_report_import' => "Import report specified by ID into framework",
      }
    end

    def cmd_besecure_help()
      print_status("besecure_help                  Display this help")
      print_status("besecure_debug                 Enable/Disable debugging")
      print_status("besecure_version               Display the version of the beSECURE server")
      print_status("besecure_apikey                Set the beSECURE API Key")
      print_status("besecure_ssl_verify            Set whether to verify or not SSL")
      print_status("besecure_hostname              Set the beSECURE Hostname")

      print_status
      print_status("REPORTS")
      print_status("=======")
      print_status("besecure_report_list           Lists reports")
      print_status("besecure_report_download       Downloads an beSECURE report specified by ID")
      print_status("besecure_report_import         Import report specified by ID into framework")
    end

    # Verify the database is connected and usable
    def database?
      if !(framework.db and framework.db.usable)
        return false
      else
        return true
      end
    end

    # Verify correct number of arguments and verify -h was not given. Return
    # true if correct number of arguments and help was not requested.
    def args?(args, min=1, max=nil)
      if not max then max = min end
      if (args.length < min or args.length > max or args[0] == "-h")
        return false
      end

      return true
    end

  #--------------------------
  # Basic Functions
  #--------------------------
  def cmd_besecure_hostname(*args)
    if args?(args)
      @hostname = args[0]
      print_good(@hostname)
    else
      print_status("Usage:")
      print_status("besecure_hostname string")
    end
  end

  def cmd_besecure_apikey(*args)
    if args?(args)
      @apikey = args[0]
      print_good(@apikey)
    else
      print_status("Usage:")
      print_status("besecure_apikey string")
    end
  end

  def cmd_besecure_ssl_verify(*args)
    if args?(args)
      @ssl_verify = args[0]
      if @ssl_verify != 'yes' and @ssl_verify != 'no'
        @ssl_verify = 'yes'
      end
      print_good(@ssl_verify)
    else
      print_status("Usage:")
      print_status("besecure_ssl_verify 'yes'/'no' (default is yes)")
    end
  end

  def cmd_besecure_debug(*args)
    if args?(args)
      @debug = args[0].to_i
      print_good(@debug)
    else
      print_status("Usage:")
      print_status("besecure_debug integer")
    end
  end

  def cmd_besecure_version()
    req = Net::HTTP::Post.new('/json.cgi', initheader={'Host'=>@hostname})
    req.set_form_data({'apikey' => @apikey, 'primary' => 'interface'})

    if @debug
      print_status(req.body)
    end
      
    http = Net::HTTP::new(@hostname, 443)
    if @debug
      http.set_debug_output($stdout) # Logger.new("foo.log") works too
    end

    http.use_ssl = true
    if @ssl_verify == 'no'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
    
    res = http.start {|http| http.request(req)}

    unless res
      print_error("#{@hostname} - Connection timed out")
      return ''
    end

    body = ''
    begin
      body = JSON.parse(res.body)
    rescue JSON::ParserError
      print_error("#{@hostname} - Unable to parse the response")
      return ''
    end

    if body['error']
      print_error("#{@hostname} - An error occured:")
      print_error(body)
      return ''
    end

    print_good(body['version'])
  end

  #--------------------------
  # Report Functions
  #--------------------------
  
    def cmd_besecure_report_list(*args)
      tbl = Rex::Text::Table.new(
            'Columns' => ["ID", "Name", "Hosts"])
      
      if @hostname.empty?
        print_error("Missing host value")
        return ''
      end
      
      req = Net::HTTP::Post.new('/json.cgi', initheader={'Host'=>@hostname})
      req.set_form_data({'apikey' => @apikey, 'primary' => 'admin', 'secondary' => 'networks', 'action' => 'returnnetworks', 'search_limit' => 10000 })

      if @debug
        print_status(req.body)
      end

      http = Net::HTTP::new(@hostname, 443)
      if @debug
        http.set_debug_output($stdout) # Logger.new("foo.log") works too
      end

      http.use_ssl = true
      if @ssl_verify == 'no'
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      end

      res = http.start {|http| http.request(req)}

      unless res
        print_error("#{@hostname} - Connection timed out")
        return ''
      end
      
      body = ''
      begin
        body = JSON.parse(res.body)
      rescue JSON::ParserError
        print_error("#{@hostname} - Unable to parse the response")
        return ''
      end
  
      if body['error']
        print_error("#{@hostname} - An error occured:")
        print_error(body)
        return ''
      end

      data = body['data']
      data.each do |item|
        tbl << [ item['ID'], item['Name'], item['PrettyRange']]
      end

      # print_good(body)
  
      print_good("beSECURE list of reports")
      print_line
      print_line tbl.to_s
      print_line
    end

    def cmd_besecure_report_download(*args)
      if args?(args, 4)
        req = Net::HTTP::Post.new('/json.cgi', initheader={'Host'=>@hostname})
        format_file = args[1]
        req.set_form_data({'apikey' => @apikey, 'primary' => 'vulnerabilities', 'secondary' => 'report', 'action' => 'getreport', 'network' => args[0], 'format' => format_file})

        http = Net::HTTP::new(@hostname, 443)
        if @debug
          http.set_debug_output($stdout) # Logger.new("foo.log") works too
        end

        http.use_ssl = true
        if @ssl_verify == 'no'
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        end

        res = http.start {|http| http.request(req)}

        unless res
          print_error("#{@hostname} - Connection timed out")
          return ''
        end

        body = ''
        begin
          body = JSON.parse(res.body)
        rescue JSON::ParserError
          print_error("#{@hostname} - Unable to parse the response")
          return ''
        end
    
        if body['error']
          print_error("#{@hostname} - An error occured:")
          print_error(body)
          return ''
        end

        decompressed = ''
        if format_file != 'json'
          compressed_base64 = body["compresseddata"]
          compressed = Base64.decode64(compressed_base64)
          decompressed = Zlib::Inflate.inflate(compressed)
        else
          decompressed = body
        end

        if @debug
          print_status(decompressed)
        end

        ::FileUtils.mkdir_p(args[2])
        name = ::File.join(args[2], args[3])
        print_status("Saving report to #{name}")
        output = ::File.new(name, "w")
        output.puts(decompressed)
        output.close
       
        ###
        # Return the report
        return decompressed
      else
        print_status("Usage: besecure_report_download <network_id> <format_name> <path> <report_name>")
      end
      
      return ''
    end

    def cmd_besecure_report_import(*args)
      if args?(args, 2)
        if !database?
          print_error("Database not ready")
          return ''
        end
        
        tempfile = Tempfile.new('results')

        res = cmd_besecure_report_download(args[0], 'nbe', File.dirname(tempfile) + "/", File.basename(tempfile) )
        if res.empty?
          print_error("An empty report has been received")
          return ''
        end

        print_status("Importing report to database.")
        framework.db.import_file({:filename => tempfile})

        tempfile.unlink
      else
        print_status("Usage: besecure_report_import <network_id> <format_name>")
        print_status("Only the NBE and XML formats are supported for importing.")
      end
    end
  end # End beSECURE class

#------------------------------
# Plugin initialization
#------------------------------

  def initialize(framework, opts)
    super
    add_console_dispatcher(BeSECURECommandDispatcher)
    print_status("Welcome to beSECURE integration by Noam Rathaus.")
    print_status
    print_status("beSECURE integration requires a database connection. Once the ")
    print_status("database is ready, connect to the beSECURE server using besecure_connect.")
    print_status("For additional commands use besecure_help.")
    print_status

    @debug = nil
  end

  def cleanup
    remove_console_dispatcher('beSECURE')
  end

  def name
    "beSECURE"
  end

  def desc
    "Integrates with the beSECURE - open source vulnerability management"
  end
end
end
