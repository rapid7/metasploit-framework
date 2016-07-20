module Msf::DBManager::Import::Nessus
  autoload :NBE, 'msf/core/db_manager/import/nessus/nbe'
  autoload :XML, 'msf/core/db_manager/import/nessus/xml'

  include Msf::DBManager::Import::Nessus::NBE
  include Msf::DBManager::Import::Nessus::XML

  protected

  #
  # This holds all of the shared parsing/handling used by the
  # Nessus NBE and NESSUS v1 methods
  #
  def handle_nessus(wspace, hobj, port, nasl, plugin_name, severity, data,task=nil)

    addr = hobj.address
    # The port section looks like:
    #   http (80/tcp)
    p = port.match(/^([^\(]+)\((\d+)\/([^\)]+)\)/)

    if p
      name = p[1].strip
      port = p[2].to_i
      proto = p[3].downcase
    else
      port = nil
    end

    info = { :workspace => wspace, :host => hobj, :port => port, :proto => proto, :task => task }
    if name and name != "unknown" and name[-1,1] != "?"
      info[:name] = name
    end
    report_service(info)

    if nasl.nil? || nasl.empty? || nasl == 0 || nasl == "0"
      return
    end

    data.gsub!("\\n", "\n")

    refs = []

    if (data =~ /^CVE : (.*)$/)
      $1.gsub(/C(VE|AN)\-/, '').split(',').map { |r| r.strip }.each do |r|
        refs.push('CVE-' + r)
      end
    end

    if (data =~ /^BID : (.*)$/)
      $1.split(',').map { |r| r.strip }.each do |r|
        refs.push('BID-' + r)
      end
    end

    if (data =~ /^Other references : (.*)$/)
      $1.split(',').map { |r| r.strip }.each do |r|
        ref_id, ref_val = r.split(':')
        ref_val ? refs.push(ref_id + '-' + ref_val) : refs.push(ref_id)
      end
    end

    nss = 'NSS-' + nasl.to_s.strip
    refs << nss

    unless plugin_name.to_s.strip.empty?
      vuln_name = plugin_name
    else
      vuln_name = nss
    end

    vuln_info = {
      :workspace => wspace,
      :host => hobj,
      :port => port,
      :proto => proto,
      :name => vuln_name,
      :info => data,
      :refs => refs,
      :task => task,
    }
    report_vuln(vuln_info)
  end
end