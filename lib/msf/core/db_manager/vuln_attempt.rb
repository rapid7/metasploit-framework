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
end