##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'pdf-reader'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

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

    options = {
      'rhost'  =>  target.host,
      'rport'  => target.port,
      'method' => 'GET',
      'uri'    => target.request_uri
    }

    options['SSL'] = true if target.scheme.eql? 'https'

    res = send_request_raw(options)
    disconnect

    print_status "HTTP #{res.code} -- Downloaded PDF (#{res.body.length} bytes)"

    return res.code == 200 ? StringIO.new(res.body) : StringIO.new
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
