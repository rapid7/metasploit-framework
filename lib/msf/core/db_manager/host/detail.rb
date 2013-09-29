module Msf::DBManager::Host::Detail
  #
  # Populate the host_details table with additional
  # information, matched by a specific criteria
  #
  def report_host_details(host, details)
    with_connection {
      detail = Mdm::HostDetail.where(( details.delete(:key) || {} ).merge(:host_id => host.id)).first

      if detail
        details.each_pair do |k,v|
          detail[k] = v
        end
        detail.save! if detail.changed?
        detail
      else
        Mdm::HostDetail.create(details.merge(:host_id => host.id))
      end
    }
  end
end