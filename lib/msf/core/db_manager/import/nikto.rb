module Msf::DBManager::Import::Nikto
  #
  # Imports Nikto scan data from -Format xml into hosts, services, vulns, and notes.
  #
  def import_nikto_xml(args={}, &block)
    data = args[:data]
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework).name
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    doc = rexmlify(data)
    doc.elements.each do |f|
      f.elements.each('niktoscan/scandetails') do |host|
        # Get host information
        addr = host.attributes['targetip']
        next if not addr
        if bl.include? addr
          next
        else
          yield(:address,addr) if block
        end
        # Get service information
        port = host.attributes['targetport']
        next if port.to_i == 0
        uri = URI.parse(host.attributes['sitename']) rescue nil
        next unless uri and uri.scheme

        hname = host.attributes['targethostname']
        banner = host.attributes['targetbanner']

        # Report the host
        host_info = {
          :workspace => wspace,
          :host      => addr,
          :state     => Msf::HostState::Alive,
          :task      => args[:task]
        }
        host_info[:name] = hname if hname and !hname.empty? and hname != addr
        msf_import_host(host_info)

        # Report the service
        service_info = {
          :workspace => wspace,
          :host      => addr,
          :port      => port.to_i,
          :proto     => "tcp",
          :state     => "open",
          :name      => uri.scheme,
          :task      => args[:task]
        }
        service_info[:info] = banner if banner and !banner.empty?
        msf_import_service(service_info)

        # Collect and report scan descriptions.
        host.elements.each do |item|
          if item.elements['description']
            desc_text = item.elements['description'].text
            next if desc_text.nil? or desc_text.empty?
            nikto_id = item.attributes['id']
            refs_text = item.elements['references'] ? item.elements['references'].text : nil

            desc_data = {
                :workspace => wspace,
                :host      => addr,
                :type      => "service.nikto.scan.description",
                :data      => { :description => desc_text },
                :proto     => "tcp",
                :port      => port.to_i,
                :sname     => uri.scheme,
                :update    => :unique_data,
                :task      => args[:task]
            }
            # Always report it as a note.
            msf_import_note(desc_data)
            # Build references from the references element
            refs = []
            if refs_text and !refs_text.empty?
              refs_text.scan(/CVE-\d{4}-\d+/i).each do |cve|
                refs << cve.upcase
              end
              refs_text.scan(/https?:\/\/[^\s,]+/).each do |url|
                refs << "URL-#{url}"
              end
            end

            # Legacy OSVDB support
            if item.attributes['osvdbid'].to_i != 0
              refs << "OSVDB-#{item.attributes['osvdbid']}"
            end

            # Always report as a vuln, with refs when available.
            vuln_data = {
              :workspace => wspace,
              :host      => addr,
              :port      => port.to_i,
              :proto     => "tcp",
              :sname     => uri.scheme,
              :name      => "NIKTO-#{nikto_id}",
              :info      => desc_text,
              :task      => args[:task]
            }
            vuln_data[:refs] = refs if refs.any?
            msf_import_vuln(vuln_data)
          end
        end
      end
    end
  end
end
