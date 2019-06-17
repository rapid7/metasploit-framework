require 'rex/parser/nexpose_simple_nokogiri'

module Msf::DBManager::Import::Nexpose::Simple
  def import_nexpose_noko_stream(args, &block)
    if block
      doc = Rex::Parser::NexposeSimpleDocument.new(args,framework.db) {|type, data| yield type,data }
    else
      doc = Rex::Parser::NexposeSimpleDocument.new(args,self)
    end
    parser = ::Nokogiri::XML::SAX::Parser.new(doc)
    parser.parse(args[:data])
  end

  def import_nexpose_simplexml(args={}, &block)
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    wspace = args[:wspace] || args[:workspace]
    if Rex::Parser.nokogiri_loaded
      parser = "Nokogiri v#{::Nokogiri::VERSION}"
      noko_args = args.dup
      noko_args[:blacklist] = bl
      noko_args[:wspace] = wspace
      if block
        yield(:parser, parser)
        import_nexpose_noko_stream(noko_args) {|type, data| yield type,data}
      else
        import_nexpose_noko_stream(noko_args)
      end
      return true
    end
    data = args[:data]

    doc = rexmlify(data)
    doc.elements.each('/NeXposeSimpleXML/devices/device') do |dev|
      addr = dev.attributes['address'].to_s
      if bl.include? addr
        next
      else
        yield(:address,addr) if block
      end

      fprint = {}

      dev.elements.each('fingerprint/description') do |str|
        fprint[:desc] = str.text.to_s.strip
      end
      dev.elements.each('fingerprint/vendor') do |str|
        fprint[:vendor] = str.text.to_s.strip
      end
      dev.elements.each('fingerprint/family') do |str|
        fprint[:family] = str.text.to_s.strip
      end
      dev.elements.each('fingerprint/product') do |str|
        fprint[:product] = str.text.to_s.strip
      end
      dev.elements.each('fingerprint/version') do |str|
        fprint[:version] = str.text.to_s.strip
      end
      dev.elements.each('fingerprint/architecture') do |str|
        fprint[:arch] = str.text.to_s.upcase.strip
      end

      conf = {
        :workspace => wspace,
        :host      => addr,
        :state     => Msf::HostState::Alive,
        :task      => args[:task]
      }

      host = report_host(conf)
      report_import_note(wspace, host)

      report_note(
        :workspace => wspace,
        :host      => host,
        :type      => 'host.os.nexpose_fingerprint',
        :data      => fprint,
        :task      => args[:task]
      )

      # Load vulnerabilities not associated with a service
      dev.elements.each('vulnerabilities/vulnerability') do |vuln|
        vid  = vuln.attributes['id'].to_s.downcase
        refs = process_nexpose_data_sxml_refs(vuln)
        next if not refs
        report_vuln(
          :workspace => wspace,
          :host      => host,
          :name      => 'NEXPOSE-' + vid,
          :info      => vid,
          :refs      => refs,
          :task      => args[:task]
        )
      end

      # Load the services
      dev.elements.each('services/service') do |svc|
        sname = svc.attributes['name'].to_s
        sprot = svc.attributes['protocol'].to_s.downcase
        sport = svc.attributes['port'].to_s.to_i
        next if sport == 0

        name = sname.split('(')[0].strip
        info = ''

        svc.elements.each('fingerprint/description') do |str|
          info = str.text.to_s.strip
        end

        if(sname.downcase != '<unknown>')
          report_service(
              :workspace => wspace,
              :host      => host,
              :proto     => sprot,
              :port      => sport,
              :name      => name,
              :info      => info,
              :task      => args[:task]
          )
        else
          report_service(
              :workspace => wspace,
              :host      => host,
              :proto     => sprot,
              :port      => sport,
              :info      => info,
              :task      => args[:task]
          )
        end

        # Load vulnerabilities associated with this service
        svc.elements.each('vulnerabilities/vulnerability') do |vuln|
          vid  = vuln.attributes['id'].to_s.downcase
          refs = process_nexpose_data_sxml_refs(vuln)
          next if not refs
          report_vuln(
              :workspace => wspace,
              :host      => host,
              :port      => sport,
              :proto     => sprot,
              :name      => 'NEXPOSE-' + vid,
              :info      => vid,
              :refs      => refs,
              :task      => args[:task]
          )
        end
      end
    end
  end

  #
  # Nexpose Simple XML
  #
  # XXX At some point we'll want to make this a stream parser for dealing
  # with large results files
  #
  def import_nexpose_simplexml_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || args[:workspace]

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_nexpose_simplexml(args.merge(:data => data))
  end

  protected

  def process_nexpose_data_sxml_refs(vuln)
    refs = []
    vid = vuln.attributes['id'].to_s.downcase
    vry = vuln.attributes['resultCode'].to_s.upcase

    # Only process vuln-exploitable and vuln-version statuses
    return if vry !~ /^V[VE]$/

    refs = []
    vuln.elements.each('id') do |ref|
      rtyp = ref.attributes['type'].to_s.upcase
      rval = ref.text.to_s.strip
      case rtyp
      when 'CVE'
        refs << rval.gsub('CAN', 'CVE')
      when 'MS' # obsolete?
        refs << "MSB-MS-#{rval}"
      else
        refs << "#{rtyp}-#{rval}"
      end
    end

    refs << "NEXPOSE-#{vid}"
    refs
  end
end
