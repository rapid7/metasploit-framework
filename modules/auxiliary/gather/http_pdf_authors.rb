##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'pdf-reader'

class MetasploitModule < Msf::Auxiliary

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Gather PDF Authors',
      'Description' => %q{
        This module downloads PDF files and extracts the author's
        name from the document metadata.
      },
      'License'     => MSF_LICENSE,
      'Author'      => 'Brendan Coles <bcoles[at]gmail.com>'))
    register_options(
      [
        OptString.new('URL', [ false, 'The URL of a PDF to analyse', '' ]),
        OptString.new('URL_LIST', [ false, 'File containing a list of PDF URLs to analyze', '' ]),
        OptString.new('OUTFILE', [ false, 'File to store output', '' ])
      ])
    register_advanced_options(
      [
        OptString.new('SSL_VERIFY', [ true, 'Verify SSL certificate', true ]),
        OptString.new('PROXY', [ false, 'Proxy server to route connection. <host>:<port>', nil ]),
        OptString.new('PROXY_USER', [ false, 'Proxy Server User', nil ]),
        OptString.new('PROXY_PASS', [ false, 'Proxy Server Password', nil ])
      ])
  end

  def progress(current, total)
    done = (current.to_f / total.to_f) * 100
    percent = "%3.2f%%" % done.to_f
    print_status "%7s done (%d/%d files)" % [percent, current, total]
  end

  def load_urls
    return [ datastore['URL'] ] unless datastore['URL'].to_s.eql? ''

    if datastore['URL_LIST'].to_s.eql? ''
      fail_with Failure::BadConfig, 'No URL(s) specified'
    end

    unless File.file? datastore['URL_LIST'].to_s
      fail_with Failure::BadConfig, "File '#{datastore['URL_LIST']}' does not exit"
    end

    File.open(datastore['URL_LIST'], 'rb') {|f| f.read}.split(/\r?\n/)
  end

  def read(data)
    begin
      reader = PDF::Reader.new data
      return parse reader
    rescue PDF::Reader::MalformedPDFError
      print_error "Could not parse PDF: PDF is malformed"
      return
    rescue PDF::Reader::UnsupportedFeatureError
      print_error "Could not parse PDF: PDF::Reader::UnsupportedFeatureError"
      return
    rescue => e
      print_error "Could not parse PDF: Unhandled exception: #{e}"
      return
    end
  end

  def parse(reader)
    # PDF
    #print_status "PDF Version: #{reader.pdf_version}"
    #print_status "PDF Title: #{reader.info['title']}"
    #print_status "PDF Info: #{reader.info}"
    #print_status "PDF Metadata: #{reader.metadata}"
    #print_status "PDF Pages: #{reader.page_count}"

    # Software
    #print_status "PDF Creator: #{reader.info[:Creator]}"
    #print_status "PDF Producer: #{reader.info[:Producer]}"

    # Author
    reader.info[:Author].class == String ? reader.info[:Author].split(/\r?\n/).first : ''
  end

  def download(url)
    print_status "Downloading '#{url}'"

    begin
      target = URI.parse url
      raise 'Invalid URL' unless target.scheme =~ %r{https?}
      raise 'Invalid URL' if target.host.to_s.eql? ''
    rescue => e
      print_error "Could not parse URL: #{e}"
      return
    end

    clnt = Net::HTTP::Proxy(@proxysrv, @proxyport, @proxyuser, @proxypass).new(target.host, target.port)

    if target.scheme.eql? 'https'
      clnt.use_ssl = true
      clnt.verify_mode = datastore['SSL_VERIFY'] ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
    end

    headers = {
      'User-Agent' => 'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/525.13'
    }

    begin
      res = clnt.get2 target.request_uri, headers
    rescue => e
      print_error "Connection failed: #{e}"
      return
    end

    unless res
      print_error 'Connection failed'
      return
    end

    print_status "HTTP #{res.code} -- Downloaded PDF (#{res.body.length} bytes)"

    contents = StringIO.new
    contents.puts res.body
    contents
  end

  def write_output(data)
    return if datastore['OUTFILE'].to_s.eql? ''

    print_status "Writing data to #{datastore['OUTFILE']}..."
    file_name = datastore['OUTFILE']

    if FileTest::exist?(file_name)
      print_status 'OUTFILE already exists, appending..'
    end

    File.open(file_name, 'ab') do |fd|
      fd.write(data)
    end
  end

  def run
    if datastore['PROXY']
      @proxysrv, @proxyport = datastore['PROXY'].split(':')
      @proxyuser = datastore['PROXY_USER']
      @proxypass = datastore['PROXY_PASS']
    else
      @proxysrv, @proxyport = nil, nil
    end

    urls = load_urls
    print_status "Processing #{urls.size} URLs..."
    authors = []
    max_len = 256
    urls.each_with_index do |url, index|
      next if url.blank?
      contents = download url
      next if contents.blank?
      author = read contents
      unless author.blank?
        print_good "PDF Author: #{author}"
        if author.length > max_len
          print_warning "Warning: Truncated author's name at #{max_len} characters"
          authors << author[0...max_len]
        else
          authors << author
        end
      end
      progress(index + 1, urls.size)
    end

    print_line

    if authors.empty?
      print_status 'Found no authors'
      return
    end

    print_good "Found #{authors.size} authors: #{authors.join ', '}"
    write_output authors.join "\n"
  end
end
