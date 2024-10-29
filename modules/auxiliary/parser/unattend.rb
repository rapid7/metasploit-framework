##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


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
          ['URL', 'https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-8.1-and-8/ff715801(v=win.10)'],
          ['URL', 'https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749415(v=ws.10)'],
          ['URL', 'https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc732280(v=ws.10)']
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

