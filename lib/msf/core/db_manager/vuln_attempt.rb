module Msf::DBManager::VulnAttempt
  def report_vuln_attempt(vuln, opts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    return if not vuln
    info = {}

    # Opts can be keyed by strings or symbols
    ::Mdm::VulnAttempt.column_names.each do |kn|
      k = kn.to_sym
      next if ['id', 'vuln_id'].include?(kn)
      info[k] = opts[kn] if opts[kn]
      info[k] = opts[k]  if opts[k]
    end

    return unless info[:attempted_at]

    vuln.vuln_attempts.create(info)
  }
  end

  #
  # This methods returns a list of all vulnerability attempts in the database
  #
  def vuln_attempts(opts)
  ::ActiveRecord::Base.connection_pool.with_connection {
    # If we have the ID, there is no point in creating a complex query.
    if opts[:id] && !opts[:id].to_s.empty?
      return Array.wrap(Mdm::VulnAttempt.find(opts[:id]))
    end

    # 'workspace' is not a valid attribute for Mdm::VulnAttempt. Remove it.
    opts.delete(:workspace)

    search_term = opts.delete(:search_term)
    if search_term && !search_term.empty?
      column_search_conditions = Msf::Util::DBManager.create_all_column_search_conditions(Mdm::VulnAttempt, search_term)
      Mdm::VulnAttempt.where(opts).where(column_search_conditions)
    else
      Mdm::VulnAttempt.where(opts)
    end
  }
  end
end
