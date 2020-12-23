require 'csv'

module Msf::DBManager::Import::Spiceworks
  def import_spiceworks_csv(args={}, &block)
    data = args[:data]
    wspace = Msf::Util::DBManager.process_opts_workspace(args, framework).name
    bl = validate_ips(args[:blacklist]) ? args[:blacklist].split : []
    CSV.parse(data) do |row|
      next unless (["Name", "Manufacturer", "Device Type"] & row).empty? #header
      name = row[0]
      manufacturer = row[1]
      device = row[2]
      model = row[3]
      ip = row[4]
      serialno = row[5]
      location = row[6]
      os = row[7]

      next unless ip
      next if bl.include? ip

      conf = {
      :workspace => wspace,
      :host      => ip,
      :name      => name,
      :task      => args[:task]
      }


      if os
        report_note(
          :workspace => wspace,
          :task => args[:task],
          :host => ip,
          :type => 'host.os.spiceworks_fingerprint',
          :data => {
            :os => os.to_s.strip
          }
        )
      end

      info = []
      info << "Serial Number: #{serialno}" unless (serialno.blank? or serialno == name)
      info << "Location: #{location}" unless location.blank?
      conf[:info] = info.join(", ") unless info.empty?

      host = report_host(conf)
      report_import_note(wspace, host)
    end
  end
end
