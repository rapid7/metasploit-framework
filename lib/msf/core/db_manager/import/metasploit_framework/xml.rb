# -*- coding: binary -*-
# Handles importing of the xml format exported by Pro.  The methods are in a
# module because (1) it's just good code layout and (2) it allows the
# methods to be overridden in Pro without using alias_method_chain as
# methods defined in a class cannot be overridden by including a module
# (unless you're running Ruby 2.0 and can use prepend)
module Msf::DBManager::Import::MetasploitFramework::XML
  #
  # CONSTANTS
  #

  # Elements that can be treated as text (i.e. do not need to be
  # deserialized) in {#import_msf_web_page_element}
  MSF_WEB_PAGE_TEXT_ELEMENT_NAMES = [
      'auth',
      'body',
      'code',
      'cookie',
      'ctype',
      'location',
      'mtime'
  ]

  # Elements that can be treated as text (i.e. do not need to be
  # deserialized) in {#import_msf_web_element}.
  MSF_WEB_TEXT_ELEMENT_NAMES = [
      'created-at',
      'host',
      'path',
      'port',
      'query',
      'ssl',
      'updated-at',
      'vhost'
  ]

  # Elements that can be treated as text (i.e. do not need to be
  # deserialized) in {#import_msf_web_vuln_element}.
  MSF_WEB_VULN_TEXT_ELEMENT_NAMES = [
      'blame',
      'category',
      'confidence',
      'description',
      'method',
      'name',
      'pname',
      'proof',
      'risk'
  ]

  #
  # Instance Methods
  #

  # Import a Metasploit XML file.
  def import_msf_file(args={})
    filename = args[:filename]
    wspace = args[:wspace] || workspace

    data = ""
    ::File.open(filename, 'rb') do |f|
      data = f.read(f.stat.size)
    end
    import_msf_xml(args.merge(:data => data))
  end

  # Imports `Mdm::Note` objects from the XML element.
  #
  # @param note [Nokogiri::XML::Element] The Note element
  # @param allow_yaml [Boolean] whether to allow yaml
  # @param note_data [Hash] hash containing note attributes to be passed along
  # @return [void]
  def import_msf_note_element(note, allow_yaml, note_data={})
    note_data[:type] = nils_for_nulls(note.at("ntype").text.to_s.strip)
    note_data[:data] = nils_for_nulls(unserialize_object(note.at("data"), allow_yaml))

    if note.at("critical").text
      note_data[:critical] = true unless note.at("critical").text.to_s.strip == "NULL"
    end
    if note.at("seen").text
      note_data[:seen] = true unless note.at("critical").text.to_s.strip == "NULL"
    end
    %W{created-at updated-at}.each { |datum|
      if note.at(datum).text
        note_data[datum.gsub("-","_")] = nils_for_nulls(note.at(datum).text.to_s.strip)
      end
    }
    report_note(note_data)
  end

  # Imports web_form element using Msf::DBManager#report_web_form.
  #
  # @param element [Nokogiri::XML::Element] web_form element.
  # @param options [Hash{Symbol => Object}] options
  # @option options [Boolean] :allow_yaml (false) Whether to allow YAML when
  #   deserializing params.
  # @option options [Mdm::Workspace, nil] :workspace
  #   (Msf::DBManager#workspace) workspace under which to report the
  #   Mdm::WebForm
  # @yield [event, data]
  # @yieldparam event [:web_page] The event name
  # @yieldparam data [String] path
  # @yieldreturn [void]
  # @return [void]
  def import_msf_web_form_element(element, options={}, &notifier)
    options.assert_valid_keys(:allow_yaml, :workspace)

    import_msf_web_element(element,
                           :allow_yaml => options[:allow_yaml],
                           :notifier => notifier,
                           :type => :form,
                           :workspace => options[:workspace]) do |element, options|
      info = import_msf_text_element(element, 'method')

      # FIXME https://www.pivotaltracker.com/story/show/46578647
      # FIXME https://www.pivotaltracker.com/story/show/47128407
      unserialized_params = unserialize_object(
          element.at('params'),
          options[:allow_yaml]
      )
      info[:params] = nils_for_nulls(unserialized_params)

      info
    end
  end

  # Imports web_page element using Msf::DBManager#report_web_page.
  #
  # @param element [Nokogiri::XML::Element] web_page element.
  # @param options [Hash{Symbol => Object}] options
  # @option options [Boolean] :allow_yaml (false) Whether to allow YAML when
  #   deserializing headers.
  # @option options [Mdm::Workspace, nil] :workspace
  #   (Msf::DBManager#workspace) workspace under which to report the
  #   Mdm::WebPage.
  # @yield [event, data]
  # @yieldparam event [:web_page] The event name
  # @yieldparam data [String] path
  # @yieldreturn [void]
  # @return [void]
  def import_msf_web_page_element(element, options={}, &notifier)
    options.assert_valid_keys(:allow_yaml, :workspace)

    import_msf_web_element(element,
                           :allow_yaml => options[:allow_yaml],
                           :notifier => notifier,
                           :type => :page,
                           :workspace => options[:workspace]) do |element, options|
      info = {}

      MSF_WEB_PAGE_TEXT_ELEMENT_NAMES.each do |name|
        element_info = import_msf_text_element(element, name)
        info.merge!(element_info)
      end

      code = info[:code]

      if code
        info[:code] = code.to_i
      end

      # FIXME https://www.pivotaltracker.com/story/show/46578647
      # FIXME https://www.pivotaltracker.com/story/show/47128407
      unserialized_headers = unserialize_object(
          element.at('headers'),
          options[:allow_yaml]
      )
      info[:headers] = nils_for_nulls(unserialized_headers)

      info
    end
  end

  # Imports web_vuln element using Msf::DBManager#report_web_vuln.
  #
  # @param element [Nokogiri::XML::Element] web_vuln element.
  # @param options [Hash{Symbol => Object}] options
  # @option options [Boolean] :allow_yaml (false) Whether to allow YAML when
  #   deserializing headers.
  # @option options [Mdm::Workspace, nil] :workspace
  #   (Msf::DBManager#workspace) workspace under which to report the
  #   Mdm::WebPage.
  # @yield [event, data]
  # @yieldparam event [:web_page] The event name
  # @yieldparam data [String] path
  # @yieldreturn [void]
  # @return [void]
  def import_msf_web_vuln_element(element, options={}, &notifier)
    options.assert_valid_keys(:allow_yaml, :workspace)

    import_msf_web_element(element,
                           :allow_yaml => options[:allow_yaml],
                           :notifier => notifier,
                           :workspace => options[:workspace],
                           :type => :vuln) do |element, options|
      info = {}

      MSF_WEB_VULN_TEXT_ELEMENT_NAMES.each do |name|
        element_info = import_msf_text_element(element, name)
        info.merge!(element_info)
      end

      confidence = info[:confidence]

      if confidence
        info[:confidence] = confidence.to_i
      end

      # FIXME https://www.pivotaltracker.com/story/show/46578647
      # FIXME https://www.pivotaltracker.com/story/show/47128407
      unserialized_params = unserialize_object(
          element.at('params'),
          options[:allow_yaml]
      )
      info[:params] = nils_for_nulls(unserialized_params)

      risk = info[:risk]

      if risk
        info[:risk] = risk.to_i
      end

      info
    end
  end

  # For each host, step through services, notes, and vulns, and import
  # them.
  # TODO: loot, tasks, and reports
  def import_msf_xml(args={}, &block)
    data = args[:data]
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework).name
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    doc = Nokogiri::XML::Reader.from_memory(data)
    metadata = check_msf_xml_version!(doc.first.name)
    allow_yaml = metadata[:allow_yaml]
    btag = metadata[:root_tag]

    doc.each do |node|
      unless node.inner_xml.empty?
        case node.name
        when 'host'
          parse_host(Nokogiri::XML(node.outer_xml).at("./#{node.name}"), wspace, bl, allow_yaml, btag, args, &block)
        when 'web_site'
          parse_web_site(Nokogiri::XML(node.outer_xml).at("./#{node.name}"), wspace, allow_yaml, &block)
        when 'web_page', 'web_form', 'web_vuln'
          send(
              "import_msf_#{node.name}_element",
              Nokogiri::XML(node.outer_xml).at("./#{node.name}"),
              :allow_yaml => allow_yaml,
              :workspace => wspace,
              &block
          )
        end
      end
    end
  end

  private

  # Parses website Nokogiri::XML::Element
  def parse_web_site(web, wspace, allow_yaml, &block)
    # Import web sites
    info = {}
    info[:workspace] = wspace

    %W{host port vhost ssl comments}.each do |datum|
      if web.at(datum).respond_to? :text
        info[datum.intern] = nils_for_nulls(web.at(datum).text.to_s.strip)
      end
    end

    info[:options]   = nils_for_nulls(unserialize_object(web.at("options"), allow_yaml)) if web.at("options").respond_to?(:text)
    info[:ssl]       = (info[:ssl] and info[:ssl].to_s.strip.downcase == "true") ? true : false

    %W{created-at updated-at}.each { |datum|
      if web.at(datum).text
        info[datum.gsub("-","_")] = nils_for_nulls(web.at(datum).text.to_s.strip)
      end
    }

    report_web_site(info)
    yield(:web_site, "#{info[:host]}:#{info[:port]} (#{info[:vhost]})") if block
  end

  # Parses host Nokogiri::XML::Element
  def parse_host(host, wspace, blacklist, allow_yaml, btag, args, &block)

    host_data = {}
    host_data[:task] = args[:task]
    host_data[:workspace] = wspace

    # A regression resulted in the address field being serialized in some cases.
    # Lets handle both instances to keep things happy. See #5837 & #5985
    addr = nils_for_nulls(host.at('address'))
    return 0 unless addr

    # No period or colon means this must be in base64-encoded serialized form
    if addr !~ /[\.\:]/
      addr = unserialize_object(addr)
    end

    host_data[:host] = addr
    if blacklist.include? host_data[:host]
      return 0
    else
      yield(:address,host_data[:host]) if block
    end
    host_data[:mac] = nils_for_nulls(host.at("mac").text.to_s.strip)
    if host.at("comm").text
      host_data[:comm] = nils_for_nulls(host.at("comm").text.to_s.strip)
    end
    %W{created-at updated-at name state os-flavor os-lang os-name os-sp purpose}.each { |datum|
      if host.at(datum).text
        host_data[datum.gsub('-','_')] = nils_for_nulls(host.at(datum).text.to_s.strip)
      end
    }
    host_address = host_data[:host].dup # Preserve after report_host() deletes
    hobj = report_host(host_data)

    host.xpath("host_details/host_detail").each do |hdet|
      hdet_data = {}
      hdet.elements.each do |det|
        next if ["id", "host-id"].include?(det.name)
        if det.text
          hdet_data[det.name.gsub('-','_')] = nils_for_nulls(det.text.to_s.strip)
        end
      end
      report_host_details(hobj, hdet_data)
    end

    host.xpath("exploit_attempts/exploit_attempt").each do |hdet|
      hdet_data = {}
      hdet.elements.each do |det|
        next if ["id", "host-id", "session-id", "vuln-id", "service-id", "loot-id"].include?(det.name)
        if det.text
          hdet_data[det.name.gsub('-','_')] = nils_for_nulls(det.text.to_s.strip)
        end
      end
      report_exploit_attempt(hobj, hdet_data)
    end

    host.xpath('services/service').each do |service|
      service_data = {}
      service_data[:task] = args[:task]
      service_data[:workspace] = wspace
      service_data[:host] = hobj
      service_data[:port] = nils_for_nulls(service.at("port").text.to_s.strip).to_i
      service_data[:proto] = nils_for_nulls(service.at("proto").text.to_s.strip)
      %W{created-at updated-at name state info}.each { |datum|
        if service.at(datum).text
          if datum == "info"
            service_data["info"] = nils_for_nulls(unserialize_object(service.at(datum), false))
          else
            service_data[datum.gsub("-","_")] = nils_for_nulls(service.at(datum).text.to_s.strip)
          end
        end
      }
      report_service(service_data)
    end

    host.xpath('notes/note').each do |note|
      note_data = {}
      note_data[:workspace] = wspace
      note_data[:host] = hobj
      import_msf_note_element(note,allow_yaml,note_data)
    end

    host.xpath('tags/tag').each do |tag|
      tag_data = {}
      tag_data[:addr] = host_address
      tag_data[:wspace] = wspace
      tag_data[:name] = tag.at("name").text.to_s.strip
      tag_data[:desc] = tag.at("desc").text.to_s.strip
      if tag.at("report-summary").text
        tag_data[:summary] = tag.at("report-summary").text.to_s.strip
      end
      if tag.at("report-detail").text
        tag_data[:detail] = tag.at("report-detail").text.to_s.strip
      end
      if tag.at("critical").text
        tag_data[:crit] = true unless tag.at("critical").text.to_s.strip == "NULL"
      end
      report_host_tag(tag_data)
    end

    host.xpath('vulns/vuln').each do |vuln|
      vuln_data = {}
      vuln_data[:workspace] = wspace
      vuln_data[:host] = hobj
      vuln_data[:info] = nils_for_nulls(unserialize_object(vuln.at("info"), allow_yaml))
      vuln_data[:name] = nils_for_nulls(vuln.at("name").text.to_s.strip)
      %W{created-at updated-at exploited-at}.each { |datum|
        if vuln.at(datum) and vuln.at(datum).text
          vuln_data[datum.gsub("-","_")] = nils_for_nulls(vuln.at(datum).text.to_s.strip)
        end
      }
      if vuln.at("refs")
        vuln_data[:refs] = []
        vuln.xpath("refs/ref").each do |ref|
          vuln_data[:refs] << nils_for_nulls(ref.text.to_s.strip)
        end
      end

      vobj = report_vuln(vuln_data)

      vuln.xpath("notes/note").each do |note|
        note_data = {}
        note_data[:workspace] = wspace
        note_data[:vuln_id] = vobj.id
        import_msf_note_element(note,allow_yaml,note_data)
      end

      vuln.xpath("vuln_details/vuln_detail").each do |vdet|
        vdet_data = {}
        vdet.elements.each do |det|
          next if ["id", "vuln-id"].include?(det.name)
          if det.text
            vdet_data[det.name.gsub('-','_')] = nils_for_nulls(det.text.to_s.strip)
          end
        end
        report_vuln_details(vobj, vdet_data)
      end

      vuln.xpath("vuln_attempts/vuln_attempt").each do |vdet|
        vdet_data = {}
        vdet.elements.each do |det|
          next if ["id", "vuln-id", "loot-id", "session-id"].include?(det.name)
          if det.text
            vdet_data[det.name.gsub('-','_')] = nils_for_nulls(det.text.to_s.strip)
          end
        end
        report_vuln_attempt(vobj, vdet_data)
      end
    end

    ## Handle old-style (pre 4.10) XML files
    if btag == "MetasploitV4"
      if host.at('creds').present?
        unless host.at('creds').elements.empty?
          origin = Metasploit::Credential::Origin::Import.create(filename: "console-import-#{Time.now.to_i}")

          host.xpath('creds/cred').each do |cred|
            username = cred.at('user').try(:text)
            proto    = cred.at('proto').try(:text)
            sname    = cred.at('sname').try(:text)
            port     = cred.at('port').try(:text)

            # Handle blanks by resetting to sane default values
            proto   = "tcp" if proto.blank?
            pass     = cred.at('pass').try(:text)
            pass     = "" if pass == "*MASKED*"

            cred_opts = {
                workspace: wspace.name,
                username: username,
                private_data: pass,
                private_type: 'Metasploit::Credential::Password',
                service_name: sname,
                protocol: proto,
                port: port,
                origin: origin
            }
            core = create_credential(cred_opts)
            create_credential_login(core: core,
                                    workspace_id: wspace.id,
                                    address: hobj.address,
                                    port: port,
                                    protocol: proto,
                                    service_name: sname,
                                    status: Metasploit::Model::Login::Status::UNTRIED)
          end
        end
      end
    end


    host.xpath('sessions/session').each do |sess|
      sess_id = nils_for_nulls(sess.at("id").text.to_s.strip.to_i)
      sess_data = {}
      sess_data[:host] = hobj
      %W{desc platform port stype}.each {|datum|
        if sess.at(datum).respond_to? :text
          sess_data[datum.intern] = nils_for_nulls(sess.at(datum).text.to_s.strip)
        end
      }
      %W{opened-at close-reason closed-at via-exploit via-payload}.each {|datum|
        if sess.at(datum).respond_to? :text
          sess_data[datum.gsub("-","_").intern] = nils_for_nulls(sess.at(datum).text.to_s.strip)
        end
      }
      sess_data[:datastore] = nils_for_nulls(unserialize_object(sess.at("datastore"), allow_yaml))
      if sess.at("routes")
        sess_data[:routes] = nils_for_nulls(unserialize_object(sess.at("routes"), allow_yaml)) || []
      end
      if not sess_data[:closed_at] # Fake a close if we don't already have one
        sess_data[:closed_at] = Time.now.utc
        sess_data[:close_reason] = "Imported at #{Time.now.utc}"
      end

      existing_session = get_session(
          :workspace => sess_data[:host].workspace,
          :addr => sess_data[:host].address,
          :time => sess_data[:opened_at]
      )
      this_session = existing_session || report_session(sess_data)
      next if existing_session
      sess.xpath('events/event').each do |sess_event|
        sess_event_data = {}
        sess_event_data[:session] = this_session
        %W{created-at etype local-path remote-path}.each {|datum|
          if sess_event.at(datum).respond_to? :text
            sess_event_data[datum.gsub("-","_").intern] = nils_for_nulls(sess_event.at(datum).text.to_s.strip)
          end
        }
        %W{command output}.each {|datum|
          if sess_event.at(datum).respond_to? :text
            sess_event_data[datum.gsub("-","_").intern] = nils_for_nulls(unserialize_object(sess_event.at(datum), allow_yaml))
          end
        }
        report_session_event(sess_event_data)
      end
    end
  end

  # Checks if the XML document has a format version that the importer
  # understands.
  #
  # @param name [String] the root node name produced by
  #   {Nokogiri::XML::Reader#from_memory}.
  # @return [Hash{Symbol => Object}] `:allow_yaml` is true if the format
  #   requires YAML loading when calling
  #   {Msf::DBManager#unserialize_object}.  `:root_tag` the tag name of the
  #   root element for MSF XML.
  # @raise [Msf::DBImportError] if unsupported format
  def check_msf_xml_version!(name)

    metadata = {
        # FIXME https://www.pivotaltracker.com/story/show/47128407
        :allow_yaml => false,
        :root_tag => nil
    }

    case name
    when 'MetasploitExpressV1'
      # FIXME https://www.pivotaltracker.com/story/show/47128407
      metadata[:allow_yaml] = true
      metadata[:root_tag] = 'MetasploitExpressV1'
    when 'MetasploitExpressV2'
      # FIXME https://www.pivotaltracker.com/story/show/47128407
      metadata[:allow_yaml] = true
      metadata[:root_tag] = 'MetasploitExpressV2'
    when 'MetasploitExpressV3'
      metadata[:root_tag] = 'MetasploitExpressV3'
    when 'MetasploitExpressV4'
      metadata[:root_tag] = 'MetasploitExpressV4'
    when 'MetasploitV4'
      metadata[:root_tag] = 'MetasploitV4'
    when 'MetasploitV5'
      metadata[:root_tag] = 'MetasploitV5'
    end

    unless metadata[:root_tag]
      raise Msf::DBImportError,
            'Unsupported Metasploit XML document format'
    end

    metadata
  end

  # Retrieves text of element if it exists.
  #
  # @param parent_element [Nokogiri::XML::Element] element under which element with
  #   `child_name` exists.
  # @param child_name [String] the name of the element under
  #   `parent_element` whose text should be returned
  # @return [{}] if element with child_name does not exist or does not have
  #   text.
  # @return [Hash{Symbol => String}] Maps child_name symbol to text. Text is
  #   stripped and any NULLs are converted to `nil`.
  # @return [nil] if element with `child_name` does not exist under
  #   `parent_element`.
  def import_msf_text_element(parent_element, child_name)
    child_element = parent_element.at(child_name)
    info = {}

    if child_element
      stripped = child_element.text.to_s.strip
      attribute_name = child_name.underscore.to_sym
      info[attribute_name] = nils_for_nulls(stripped)
    end

    info
  end

  # Imports web_form, web_page, or web_vuln element using
  # Msf::DBManager#report_web_form, Msf::DBManager#report_web_page, and
  # Msf::DBManager#report_web_vuln, respectively.
  #
  # @param element [Nokogiri::XML::Element] the web_form, web_page, or web_vuln
  #   element.
  # @param options [Hash{Symbol => Object}] options
  # @option options [Boolean] :allow_yaml (false) Whether to allow YAML when
  #   deserializing elements.
  # @option options [Proc] :notifier Block called with web_* event and path
  # @option options [Symbol] :type the type of web element, such as :form,
  #   :page, or :vuln.  Must correspond to a report_web_<type> method on
  # {Msf::DBManager}.
  # @option options [Mdm::Workspace, nil] :workspace
  #   (Msf::DBManager#workspace) workspace under which to report the
  #   imported record.
  # @yield [element, options]
  # @yieldparam element [Nokogiri::XML::Element] the web_form, web_page, or
  #   web_vuln element passed to {#import_msf_web_element}.
  # @yieldparam options [Hash{Symbol => Object}] options for parsing
  # @yieldreturn [Hash{Symbol => Object}] info
  # @return [void]
  # @raise [KeyError] if `:type` is not given
  def import_msf_web_element(element, options={}, &specialization)
    options.assert_valid_keys(:allow_yaml, :notifier, :type, :workspace)
    type = options.fetch(:type)

    info = {}
    info[:workspace] = options[:workspace] || self.workspace

    MSF_WEB_TEXT_ELEMENT_NAMES.each do |name|
      element_info = import_msf_text_element(element, name)
      info.merge!(element_info)
    end

    info[:ssl] = (info[:ssl] and info[:ssl].to_s.strip.downcase == "true") ? true : false

    specialized_info = specialization.call(element, options)
    info.merge!(specialized_info)

    self.send("report_web_#{type}", info)

    notifier = options[:notifier]

    if notifier
      event = "web_#{type}".to_sym
      notifier.call(event, info[:path])
    end
  end
end
