module Msf::DBManager::Vuln::Detail
  #
  # Populate the vuln_details table with additional
  # information, matched by a specific criteria
  #
  def report_vuln_details(vuln, details)
    with_connection {
      detail = Mdm::VulnDetail.where(( details.delete(:key) || {} ).merge(:vuln_id => vuln.id)).first

      if detail
        details.each_pair do |k,v|
          detail[k] = v
        end

        detail.save! if detail.changed?
        detail
      else
        Mdm::VulnDetail.create(details.merge(:vuln_id => vuln.id))
      end
    }
  end

  #
  # Update vuln_details records en-masse based on specific criteria
  # Note that this *can* update data across workspaces
  #
  def update_vuln_details(details)
    with_connection {
      criteria = details.delete(:key) || {}
      ::Mdm::VulnDetail.update(key, details)
    }
  end
end