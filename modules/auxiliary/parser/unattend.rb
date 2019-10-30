##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/parser/unattend'

class MetasploitModule < Msf::Auxiliary

  def initialize(info={})
    super( update_info( info,
        'Name'        => 'Auxilliary Parser Windows Unattend Passwords',
        'Description' => %q{
        This module parses Unattend files in the target directory.

        See also: post/windows/gather/enum_unattend
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'Ben Campbell',
        ],
      'References'    =>
        [
          ['URL', 'http://technet.microsoft.com/en-us/library/ff715801'],
          ['URL', 'http://technet.microsoft.com/en-us/library/cc749415(v=ws.10).aspx'],
          ['URL', 'http://technet.microsoft.com/en-us/library/c026170e-40ef-4191-98dd-0b9835bfa580']
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

    if datastore['PATH'].ends_with?('.xml')
      filepath = datastore['PATH']
    else
      filepath = File.join(datastore['PATH'], ext)
    end

    Dir.glob(filepath) do |item|
      print_status "Processing #{item}"
      file = File.read(item)
      begin
        xml = REXML::Document.new(file)
      rescue REXML::ParseException => e
        print_error("#{item} invalid xml format.")
        vprint_line(e.message)
        next
      end

      results = Rex::Parser::Unattend.parse(xml)
      table = Rex::Parser::Unattend.create_table(results)
      print_line table.to_s unless table.nil?
      print_line
    end
  end
end

