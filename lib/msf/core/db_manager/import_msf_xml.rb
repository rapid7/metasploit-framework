# Handles importing of the xml format exported by Pro.  The methods are in a
# module because (1) it's just good code layout and (2) it allows the
# methods to be overridden in Pro without using alias_method_chain as
# methods defined in a class cannot be overridden by including a module
# (unless you're running Ruby 2.0 and can use prepend)
module Msf::DBManager::ImportMsfXml
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

  # Imports web_form element using {Msf::DBManager#report_web_form}.
  #
  # @param element [REXML::Element] web_form element.
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
          element.elements['params'],
          options[:allow_yaml]
      )
      info[:params] = nils_for_nulls(unserialized_params)

      info
    end
  end

  # Imports web_page element using {Msf::DBManager#report_web_page}.
  #
  # @param element [REXML::Element] web_page element.
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
          element.elements['headers'],
          options[:allow_yaml]
      )
      info[:headers] = nils_for_nulls(unserialized_headers)

      info
    end
  end

  # Imports web_vuln element using {Msf::DBManager#report_web_vuln}.
  #
  # @param element [REXML::Element] web_vuln element.
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
          element.elements['params'],
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
    wspace = args[:wspace] || workspace
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    doc = rexmlify(data)
    metadata = check_msf_xml_version!(doc)
    allow_yaml = metadata[:allow_yaml]
    btag = metadata[:root_tag]

    doc.elements.each("/#{btag}/hosts/host") do |host|
      host_data = {}
      host_data[:workspace] = wspace
      host_data[:host] = nils_for_nulls(host.elements["address"].text.to_s.strip)
      if bl.include? host_data[:host]
        next
      else
        yield(:address,host_data[:host]) if block
      end
      host_data[:mac] = nils_for_nulls(host.elements["mac"].text.to_s.strip)
      if host.elements["comm"].text
        host_data[:comm] = nils_for_nulls(host.elements["comm"].text.to_s.strip)
      end
      %W{created-at updated-at name state os-flavor os-lang os-name os-sp purpose}.each { |datum|
        if host.elements[datum].text
          host_data[datum.gsub('-','_')] = nils_for_nulls(host.elements[datum].text.to_s.strip)
        end
      }
      host_address = host_data[:host].dup # Preserve after report_host() deletes
      hobj = report_host(host_data)

      host.elements.each("host_details/host_detail") do |hdet|
        hdet_data = {}
        hdet.elements.each do |det|
          next if ["id", "host-id"].include?(det.name)
          if det.text
            hdet_data[det.name.gsub('-','_')] = nils_for_nulls(det.text.to_s.strip)
          end
        end
        report_host_details(hobj, hdet_data)
      end

      host.elements.each("exploit_attempts/exploit_attempt") do |hdet|
        hdet_data = {}
        hdet.elements.each do |det|
          next if ["id", "host-id", "session-id", "vuln-id", "service-id", "loot-id"].include?(det.name)
          if det.text
            hdet_data[det.name.gsub('-','_')] = nils_for_nulls(det.text.to_s.strip)
          end
        end
        report_exploit_attempt(hobj, hdet_data)
      end

      host.elements.each('services/service') do |service|
        service_data = {}
        service_data[:workspace] = wspace
        service_data[:host] = hobj
        service_data[:port] = nils_for_nulls(service.elements["port"].text.to_s.strip).to_i
        service_data[:proto] = nils_for_nulls(service.elements["proto"].text.to_s.strip)
        %W{created-at updated-at name state info}.each { |datum|
          if service.elements[datum].text
            if datum == "info"
              service_data["info"] = nils_for_nulls(unserialize_object(service.elements[datum], false))
            else
              service_data[datum.gsub("-","_")] = nils_for_nulls(service.elements[datum].text.to_s.strip)
            end
          end
        }
        report_service(service_data)
      end

      host.elements.each('notes/note') do |note|
        note_data = {}
        note_data[:workspace] = wspace
        note_data[:host] = hobj
        note_data[:type] = nils_for_nulls(note.elements["ntype"].text.to_s.strip)
        note_data[:data] = nils_for_nulls(unserialize_object(note.elements["data"], allow_yaml))

        if note.elements["critical"].text
          note_data[:critical] = true unless note.elements["critical"].text.to_s.strip == "NULL"
        end
        if note.elements["seen"].text
          note_data[:seen] = true unless note.elements["critical"].text.to_s.strip == "NULL"
        end
        %W{created-at updated-at}.each { |datum|
          if note.elements[datum].text
            note_data[datum.gsub("-","_")] = nils_for_nulls(note.elements[datum].text.to_s.strip)
          end
        }
        report_note(note_data)
      end

      host.elements.each('tags/tag') do |tag|
        tag_data = {}
        tag_data[:addr] = host_address
        tag_data[:wspace] = wspace
        tag_data[:name] = tag.elements["name"].text.to_s.strip
        tag_data[:desc] = tag.elements["desc"].text.to_s.strip
        if tag.elements["report-summary"].text
          tag_data[:summary] = tag.elements["report-summary"].text.to_s.strip
        end
        if tag.elements["report-detail"].text
          tag_data[:detail] = tag.elements["report-detail"].text.to_s.strip
        end
        if tag.elements["critical"].text
          tag_data[:crit] = true unless tag.elements["critical"].text.to_s.strip == "NULL"
        end
        report_host_tag(tag_data)
      end

      host.elements.each('vulns/vuln') do |vuln|
        vuln_data = {}
        vuln_data[:workspace] = wspace
        vuln_data[:host] = hobj
        vuln_data[:info] = nils_for_nulls(unserialize_object(vuln.elements["info"], allow_yaml))
        vuln_data[:name] = nils_for_nulls(vuln.elements["name"].text.to_s.strip)
        %W{created-at updated-at exploited-at}.each { |datum|
          if vuln.elements[datum] and vuln.elements[datum].text
            vuln_data[datum.gsub("-","_")] = nils_for_nulls(vuln.elements[datum].text.to_s.strip)
          end
        }
        if vuln.elements["refs"]
          vuln_data[:refs] = []
          vuln.elements.each("refs/ref") do |ref|
            vuln_data[:refs] << nils_for_nulls(ref.text.to_s.strip)
          end
        end

        vobj = report_vuln(vuln_data)

        vuln.elements.each("vuln_details/vuln_detail") do |vdet|
          vdet_data = {}
          vdet.elements.each do |det|
            next if ["id", "vuln-id"].include?(det.name)
            if det.text
              vdet_data[det.name.gsub('-','_')] = nils_for_nulls(det.text.to_s.strip)
            end
          end
          report_vuln_details(vobj, vdet_data)
        end

        vuln.elements.each("vuln_attempts/vuln_attempt") do |vdet|
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

      host.elements.each('creds/cred') do |cred|
        cred_data = {}
        cred_data[:workspace] = wspace
        cred_data[:host] = hobj
        %W{port ptype sname proto proof active user pass}.each {|datum|
          if cred.elements[datum].respond_to? :text
            cred_data[datum.intern] = nils_for_nulls(cred.elements[datum].text.to_s.strip)
          end
        }
        %W{created-at updated-at}.each { |datum|
          if cred.elements[datum].respond_to? :text
            cred_data[datum.gsub("-","_")] = nils_for_nulls(cred.elements[datum].text.to_s.strip)
          end
        }
        %W{source-type source-id}.each { |datum|
          if cred.elements[datum].respond_to? :text
            cred_data[datum.gsub("-","_").intern] = nils_for_nulls(cred.elements[datum].text.to_s.strip)
          end
        }
        if cred_data[:pass] == "<masked>"
          cred_data[:pass] = ""
          cred_data[:active] = false
        elsif cred_data[:pass] == "*BLANK PASSWORD*"
          cred_data[:pass] = ""
        end
        report_cred(cred_data)
      end

      host.elements.each('sessions/session') do |sess|
        sess_id = nils_for_nulls(sess.elements["id"].text.to_s.strip.to_i)
        sess_data = {}
        sess_data[:host] = hobj
        %W{desc platform port stype}.each {|datum|
          if sess.elements[datum].respond_to? :text
            sess_data[datum.intern] = nils_for_nulls(sess.elements[datum].text.to_s.strip)
          end
        }
        %W{opened-at close-reason closed-at via-exploit via-payload}.each {|datum|
          if sess.elements[datum].respond_to? :text
            sess_data[datum.gsub("-","_").intern] = nils_for_nulls(sess.elements[datum].text.to_s.strip)
          end
        }
        sess_data[:datastore] = nils_for_nulls(unserialize_object(sess.elements["datastore"], allow_yaml))
        if sess.elements["routes"]
          sess_data[:routes] = nils_for_nulls(unserialize_object(sess.elements["routes"], allow_yaml)) || []
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
        sess.elements.each('events/event') do |sess_event|
          sess_event_data = {}
          sess_event_data[:session] = this_session
          %W{created-at etype local-path remote-path}.each {|datum|
            if sess_event.elements[datum].respond_to? :text
              sess_event_data[datum.gsub("-","_").intern] = nils_for_nulls(sess_event.elements[datum].text.to_s.strip)
            end
          }
          %W{command output}.each {|datum|
            if sess_event.elements[datum].respond_to? :text
              sess_event_data[datum.gsub("-","_").intern] = nils_for_nulls(unserialize_object(sess_event.elements[datum], allow_yaml))
            end
          }
          report_session_event(sess_event_data)
        end
      end
    end

    # Import web sites
    doc.elements.each("/#{btag}/web_sites/web_site") do |web|
      info = {}
      info[:workspace] = wspace

      %W{host port vhost ssl comments}.each do |datum|
        if web.elements[datum].respond_to? :text
          info[datum.intern] = nils_for_nulls(web.elements[datum].text.to_s.strip)
        end
      end

      info[:options]   = nils_for_nulls(unserialize_object(web.elements["options"], allow_yaml)) if web.elements["options"].respond_to?(:text)
      info[:ssl]       = (info[:ssl] and info[:ssl].to_s.strip.downcase == "true") ? true : false

      %W{created-at updated-at}.each { |datum|
        if web.elements[datum].text
          info[datum.gsub("-","_")] = nils_for_nulls(web.elements[datum].text.to_s.strip)
        end
      }

      report_web_site(info)
      yield(:web_site, "#{info[:host]}:#{info[:port]} (#{info[:vhost]})") if block
    end

    %W{page form vuln}.each do |wtype|
      doc.elements.each("/#{btag}/web_#{wtype}s/web_#{wtype}") do |element|
        send(
            "import_msf_web_#{wtype}_element",
            element,
            :allow_yaml => allow_yaml,
            :workspace => wspace,
            &block
        )
      end
    end
  end

  private

  # Checks if the XML document has a format version that the importer
  # understands.
  #
  # @param document [REXML::Document] a REXML::Document produced by
  #   {Msf::DBManager#rexmlify}.
  # @return [Hash{Symbol => Object}] `:allow_yaml` is true if the format
  #   requires YAML loading when calling
  #   {Msf::DBManager#unserialize_object}.  `:root_tag` the tag name of the
  #   root element for MSF XML.
  # @raise [Msf::DBImportError] if unsupported format
  def check_msf_xml_version!(document)
    metadata = {
        # FIXME https://www.pivotaltracker.com/story/show/47128407
        :allow_yaml => false,
        :root_tag => nil
    }

    if document.elements['MetasploitExpressV1']
      # FIXME https://www.pivotaltracker.com/story/show/47128407
      metadata[:allow_yaml] = true
      metadata[:root_tag] = 'MetasploitExpressV1'
    elsif document.elements['MetasploitExpressV2']
      # FIXME https://www.pivotaltracker.com/story/show/47128407
      metadata[:allow_yaml] = true
      metadata[:root_tag] = 'MetasploitExpressV2'
    elsif document.elements['MetasploitExpressV3']
      metadata[:root_tag] = 'MetasploitExpressV3'
    elsif document.elements['MetasploitExpressV4']
      metadata[:root_tag] = 'MetasploitExpressV4'
    elsif document.elements['MetasploitV4']
      metadata[:root_tag] = 'MetasploitV4'
    end

    unless metadata[:root_tag]
      raise Msf::DBImportError,
            'Unsupported Metasploit XML document format'
    end

    metadata
  end

  # Retrieves text of element if it exists.
  #
  # @param parent_element [REXML::Element] element under which element with
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
    child_element = parent_element.elements[child_name]
    info = {}

    if child_element
      stripped = child_element.text.to_s.strip
      attribute_name = child_name.underscore.to_sym
      info[attribute_name] = nils_for_nulls(stripped)
    end

    info
  end

  # Imports web_form, web_page, or web_vuln element using
  # {Msf::DBManager#report_web_form}, {Msf::DBManager#report_web_page}, and
  # {Msf::DBManager#report_web_vuln}, respectively.
  #
  # @param element [REXML::Element] the web_form, web_page, or web_vuln
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
  # @yieldparam element [REXML::Element] the web_form, web_page, or
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
