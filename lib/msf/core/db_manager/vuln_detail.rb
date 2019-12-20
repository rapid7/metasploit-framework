module Msf::DBManager::VulnDetail
  #
  # Populate the vuln_details table with additional
  # information, matched by a specific criteria
  #
  def report_vuln_details(vuln, details)
  ::ActiveRecord::Base.connection_pool.with_connection {
    detail = ::Mdm::VulnDetail.where(( details.delete(:key) || {} ).merge(:vuln_id => vuln.id)).first
    if detail
      details.each_pair do |k,v|
        detail[k] = v
      end
      detail.save! if detail.changed?
      detail
    else
      detail = ::Mdm::VulnDetail.create(details.merge(:vuln_id => vuln.id))
    end
  }
  end

  #
  # Update vuln_details records en-masse based on specific criteria
  # Note that this *can* update data across workspaces
  #
  def update_vuln_details(details)
  ::ActiveRecord::Base.connection_pool.with_connection {
    criteria = details.delete(:key) || {}
    vuln_detail = ::Mdm::VulnDetail.find(key)
    vuln_detail.update!(criteria)
    return vuln_detail
  }
  end
end
