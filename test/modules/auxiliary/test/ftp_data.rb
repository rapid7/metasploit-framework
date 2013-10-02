##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Ftp

  def initialize
    super(
      'Name'	      => 'FTP Client Exploit Mixin DATA test Exploit',
      'Version'      => '$Revision$',
      'Description'  => 'This module tests the "DATA" functionality of the ftp client exploit mixin.',
      'Author'	      => [ 'Thomas Ring', 'jduck' ],
      'License'      => MSF_LICENSE
    )


    register_options(
      [
        OptString.new('UPLOADDIR', [ true,  "The directory to use for the upload test", '/incoming' ])
      ]
    )
  end

  def run

    begin
      if (not connect_login)
        return
      end

      curdir = ""

      # change to the upload directory
      result = send_cmd( ["CWD", datastore['UPLOADDIR']], true )
      print_status("CWD response: #{result.inspect}")

      # find out what the server thinks this dir is
      result = send_cmd( ["PWD"], true )
      print_status("PWD response: #{result.inspect}")
      if (result =~ /257\s\"(.+)\"/)
        curdir = $1
      end
      curdir = "/" + curdir if curdir[0] != "/"
      curdir << "/" if curdir[-1,1] != "/"

      # generate some data to upload
      data = Rex::Text.rand_text_alphanumeric(1024)
      #print_status("data:\n" + Rex::Text.to_hex_dump(data))

      # test putting data
      result = send_cmd_data(["PUT", curdir+"test"], data, "I")
      print_status("PUT response: #{result.inspect}")

      # test fallthrough
      result = send_cmd_data(["HELP"], true)
      print_status("HELP response: #{result.inspect}")

      # test listing directory
      result = send_cmd_data(["LS", curdir], "A")
      print_status("LS response: #{result.inspect}")

      # test getting file
      result = send_cmd_data(["GET", curdir+"test"], "A")
      print_status("GET response: #{result[0].inspect}")

      # see if it matches
      if (result[1] != data)
        print_error("Data doesn't match!")
      else
        print_good("Data downloaded matches what we uploaded!")
      end

      # adios
      result = send_cmd( ["QUIT"], true )
      print_status("QUIT response: #{result.inspect}")

    ensure
      disconnect
    end

  end

end
