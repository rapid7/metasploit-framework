module Msf::DBManager::Import::Nikto
  #
  # Imports Nikto scan data from -Format xml as notes.
  #
  def import_nikto_xml(args={}, &block)
    data = args[:data]
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework).name
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    doc = rexmlify(data)
    doc.elements.each do |f|
      f.elements.each('scandetails') do |host|
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
        # Collect and report scan descriptions.
        host.elements.each do |item|
          if item.elements['description']
            desc_text = item.elements['description'].text
            next if desc_text.nil? or desc_text.empty?
            desc_data = {
                :workspace => wspace,
                :host      => addr,
                :type      => "service.nikto.scan.description",
                :data      => desc_text,
                :proto     => "tcp",
                :port      => port.to_i,
                :sname     => uri.scheme,
                :update    => :unique_data,
                :task      => args[:task]
            }
            # Always report it as a note.
            report_note(desc_data)
            # Sometimes report it as a vuln, too.
            # XXX: There's a Vuln.info field but nothing reads from it? See Bug #5837
            if item.attributes['osvdbid'].to_i != 0
              desc_data[:refs] = ["OSVDB-#{item.attributes['osvdbid']}"]
              desc_data[:name] = "NIKTO-#{item.attributes['id']}"
              desc_data.delete(:data)
              desc_data.delete(:type)
              desc_data.delete(:update)
              report_vuln(desc_data)
            end
          end
        end
      end
    end
  end
end
