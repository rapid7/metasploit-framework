##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex/parser/group_policy_preferences'

class Metasploit3 < Msf::Auxiliary

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Auxilliary Parser Windows Group Policy Preference Passwords',
      'Description'   => %q{
        This module parses Group Policy Preference files in the target directory.

        See also: post/windows/gather/credentials/gpp
      },
      'License'       => MSF_LICENSE,
      'Author'        =>[
        'Ben Campbell <eat_meatballs[at]hotmail.co.uk>',
        ],
      'References'    =>
        [
          ['URL', 'http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences'],
          ['URL', 'http://msdn.microsoft.com/en-us/library/cc232604(v=prot.13)'],
          ['URL', 'http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html'],
          ['URL', 'http://blogs.technet.com/grouppolicy/archive/2009/04/22/passwords-in-group-policy-preferences-updated.aspx']
        ],
    ))

    register_options([
      OptPath.new('PATH', [true, 'Directory or file to parse.']),
      OptBool.new('RECURSIVE', [true, 'Recursively check for files', false]),
    ])
  end

  def run
    if datastore['RECURSIVE']
      ext = "**/*.xml"
    else
      ext = "/*.xml"
    end

    if datastore['PATH'].ends_with('.xml')
      filepath = datastore['PATH']
    else
      filepath = File.join(datastore['PATH'], ext)
    end

    Dir.glob(filepath) do |item|
      print_status "Processing #{item}"
      xml = File.read(item)
      filetype = File.basename(item.gsub("\\","/"))
      results = Rex::Parser::GPP.parse(xml)
      tables = Rex::Parser::GPP.create_tables(results, filetype)
      tables.each do |table|
        print_line table.to_s
      end
    end

  end
end

