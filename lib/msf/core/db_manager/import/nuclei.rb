module Msf::DBManager::Import::Nuclei
  #
  # Imports Nuclei scan results in JSON format.
  #
  def import_nuclei_json(args = {}, &block)
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework).name
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    JSON.parse(args[:data]).each do |data|
      next if data.blank?

      ip = data['ip']

      next if ip.blank?
      next if bl.include?(ip)

      yield(:address, ip) if block

      matched_at = data['matched-at']
      uri = URI.parse(matched_at.include?('://') ? matched_at : "tcp://#{matched_at}")
      vhost = uri.host
      port = uri.port.to_i
      service = uri.scheme

      template_id = data['template-id']
      matcher_name = data['matcher-name']

      info = data['info']
      name = info['name']
      description = info['description'].to_s.strip
      severity = info['severity']

      desc_text = [template_id, name, matcher_name, description].join("\n").strip

      note = {
        workspace: wspace,
        host: ip,
        vhost: vhost,
        port: port,
        proto: 'tcp',
        sname: service,
        type: 'host.nuclei.scan',
        data: desc_text,
        update: :unique_data,
        task: args[:task]
      }

      report_note(note)

      next unless %w[low medium high critical].include?(severity)

      references = info['reference'] || []
      curl_command = data['curl-command']
      extracted_results = data['extracted-results']
      proof = [curl_command, extracted_results].join("\n\n")

      vuln = {
        workspace: wspace,
        host: ip,
        vhost: vhost,
        port: port,
        proto: 'tcp',
        sname: service,
        name: name,
        info: desc_text,
        proof: proof,
        refs: references,
        task: args[:task]
      }

      report_vuln(vuln)
    end
  end

  #
  # Imports Nuclei scan results in JSON Lines (JSONL) format.
  #
  def import_nuclei_jsonl(args = {}, &block)
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework).name
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []

    args[:data].each_line do |line|
      next if line.strip.blank?

      data = JSON.parse(line)

      next if data.blank?

      ip = data['ip']

      next if ip.blank?
      next if bl.include?(ip)

      yield(:address, ip) if block

      matched_at = data['matched-at']
      uri = URI.parse(matched_at.include?('://') ? matched_at : "tcp://#{matched_at}")
      vhost = uri.host
      port = uri.port.to_i
      service = uri.scheme

      template_id = data['template-id']
      matcher_name = data['matcher-name']

      info = data['info']
      name = info['name']
      description = info['description'].to_s.strip
      severity = info['severity']

      desc_text = [template_id, name, matcher_name, description].join("\n").strip

      note = {
        workspace: wspace,
        host: ip,
        vhost: vhost,
        port: port,
        proto: 'tcp',
        sname: service,
        type: 'host.nuclei.scan',
        data: desc_text,
        update: :unique_data,
        task: args[:task]
      }

      report_note(note)

      next unless %w[low medium high critical].include?(severity)

      references = info['reference'] || []
      curl_command = data['curl-command']
      extracted_results = data['extracted-results']
      proof = [curl_command, extracted_results].join("\n\n")

      vuln = {
        workspace: wspace,
        host: ip,
        vhost: vhost,
        port: port,
        proto: 'tcp',
        sname: service,
        name: name,
        info: desc_text,
        proof: proof,
        refs: references,
        task: args[:task]
      }

      report_vuln(vuln)
    end
  end
end
