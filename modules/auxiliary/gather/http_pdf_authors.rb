##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'pdf-reader'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Gather PDF Authors',
      'Description' => %q{
        This module downloads PDF documents and extracts the author's
        name from the document metadata.

        This module expects a URL to be provided using the URL option.
        Alternatively, multiple URLs can be provided by supplying the
        path to a file containing a list of URLs in the URL_LIST option.

        The URL_TYPE option is used to specify the type of URLs supplied.

        By specifying 'pdf' for the URL_TYPE, the module will treat
        the specified URL(s) as PDF documents. The module will
        download the documents and extract the authors' names from the
        document metadata.

        By specifying 'html' for the URL_TYPE, the module will treat
        the specified URL(s) as HTML pages. The module will scrape the
        pages for links to PDF documents, download the PDF documents,
        and extract the author's name from the document metadata.
      },
      'License'     => MSF_LICENSE,
      'Author'      => 'Brendan Coles <bcoles[at]gmail.com>'))
    register_options(
      [
        OptString.new('URL', [ false, 'The target URL', '' ]),
        OptString.new('URL_LIST', [ false, 'File containing a list of target URLs', '' ]),
        OptEnum.new('URL_TYPE', [ true, 'The type of URL(s) specified', 'html', [ 'pdf', 'html' ] ]),
        OptBool.new('STORE_LOOT', [ false, 'Store authors in loot', true ])
      ])
    deregister_options 'RHOST', 'RHOSTS', 'RPORT', 'VHOST', 'SSL'
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
      fail_with Failure::BadConfig, "File '#{datastore['URL_LIST']}' does not exist"
    end

    File.open(datastore['URL_LIST'], 'rb') { |f| f.read }.split(/\r?\n/)
  end

  def read(data)
    Timeout.timeout(10) do
      reader = PDF::Reader.new data
      return parse reader
    end
  rescue PDF::Reader::MalformedPDFError
    print_error "Could not parse PDF: PDF is malformed (MalformedPDFError)"
    return
  rescue PDF::Reader::UnsupportedFeatureError
    print_error "Could not parse PDF: PDF contains unsupported features (UnsupportedFeatureError)"
    return
  rescue SystemStackError
    print_error "Could not parse PDF: PDF is malformed (SystemStackError)"
    return
  rescue SyntaxError
    print_error "Could not parse PDF: PDF is malformed (SyntaxError)"
    return
  rescue Timeout::Error
    print_error "Could not parse PDF: PDF is malformed (Timeout)"
    return
  rescue => e
    print_error "Could not parse PDF: Unhandled exception: #{e}"
    return
  end

  def parse(reader)
    # PDF
    # print_status "PDF Version: #{reader.pdf_version}"
    # print_status "PDF Title: #{reader.info['title']}"
    # print_status "PDF Info: #{reader.info}"
    # print_status "PDF Metadata: #{reader.metadata}"
    # print_status "PDF Pages: #{reader.page_count}"

    # Software
    # print_status "PDF Creator: #{reader.info[:Creator]}"
    # print_status "PDF Producer: #{reader.info[:Producer]}"

    # Author
    reader.info[:Author].class == String ? reader.info[:Author].split(/\r?\n/).first : ''
  end

  def run
    urls = load_urls

    if datastore['URL_TYPE'].eql? 'html'
      urls = extract_pdf_links urls

      if urls.empty?
        print_error 'Found no links to PDF files'
        return
      end

      print_line
      print_good "Found links to #{urls.size} PDF files:"
      print_line urls.join "\n"
      print_line
    end

    authors = extract_authors urls

    print_line

    if authors.empty?
      print_status 'Found no authors'
      return
    end

    print_good "Found #{authors.size} authors: #{authors.join ', '}"

    return unless datastore['STORE_LOOT']

    p = store_loot 'pdf.authors', 'text/plain', nil, authors.join("\n"), 'pdf.authors.txt', 'PDF authors'
    print_good "File saved in: #{p}"
  end

  def extract_pdf_links(urls)
    print_status "Processing #{urls.size} URLs..."

    pdf_urls = []
    urls.each_with_index do |url, index|
      next if url.blank?
      html = download url
      next if html.blank?
      doc = Nokogiri::HTML html
      doc.search('a[href]').select { |n| n['href'][/(\.pdf$|\.pdf\?)/] }.map do |n|
        pdf_urls << URI.join(url, n['href']).to_s
      end
      progress(index + 1, urls.size)
    end

    pdf_urls.uniq
  end

  def extract_authors(urls)
    print_status "Processing #{urls.size} URLs..."

    authors = []
    max_len = 256
    urls.each_with_index do |url, index|
      next if url.blank?
      file = download url
      next if file.blank?
      pdf = StringIO.new
      pdf.puts file
      author = read pdf
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

    authors.uniq
  end
end
