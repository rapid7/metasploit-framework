# Constants indicating the reason for an unsuccessful module attempt
module Msf::Module::Failure
  # The exploit settings were incorrect
  BadConfig       = 'bad-config'

  # The network service disconnected us mid-attempt
  Disconnected    = 'disconnected'

  # The application replied indication we do not have access
  NoAccess        = 'no-access'

  # No confidence in success or failure
  None            = 'none'

  # The target is not compatible with this exploit or settings
  NoTarget        = 'no-target'

  # The application endpoint or specific service was not found
  NotFound        = 'not-found'

  # The application response indicated it was not vulnerable
  NotVulnerable   = 'not-vulnerable'

  # The payload was delivered but no session was opened (AV, network, etc)
  PayloadFailed   = 'payload-failed'

  # The exploit triggered some form of timeout
  TimeoutExpired  = 'timeout-expired'

  # The application replied in an unexpected fashion
  UnexpectedReply = 'unexpected-reply'

  # No confidence in success or failure
  Unknown         = 'unknown'

  # The network service was unreachable (connection refused, etc)
  Unreachable     = 'unreachable'

  # The exploit was interrupted by the user
  UserInterrupt   = 'user-interrupt'

  # Map a {Msf::Exploit::CheckCode} to the corresponding fail_reason constant.
  #
  # @param check_code [Msf::Exploit::CheckCode]
  # @return [String, nil] a Failure constant, or nil if unmapped
  def self.fail_reason_from_check_code(check_code)
    return nil unless check_code.respond_to?(:code)

    case check_code.code
    when Msf::Exploit::CheckCode::Vulnerable.code, Msf::Exploit::CheckCode::Appears.code
      None
    when Msf::Exploit::CheckCode::Safe.code
      NotVulnerable
    when Msf::Exploit::CheckCode::Detected.code, Msf::Exploit::CheckCode::Unknown.code
      Unknown
    end
  end


  def report_failure
    return unless framework.db and framework.db.active

    info = {
      timestamp: Time.now.utc,
      workspace: framework.db.find_workspace(self.workspace),
      module: self.fullname,
      fail_reason: self.fail_reason,
      fail_detail: self.fail_detail,
      username: self.owner,
      refs: self.references,
      run_id: self.datastore['RUN_ID']
    }
    info[:target_name] = self.target.name if self.respond_to?(:target)

    # Enrich attempt data with check result details when available
    if self.respond_to?(:check_code) && self.check_code.is_a?(Msf::Exploit::CheckCode)
      info[:check_code] = self.check_code.code
      info[:check_detail] = self.check_code.reason || self.check_code.message
      mapped_reason = Msf::Module::Failure.fail_reason_from_check_code(self.check_code)
      info[:fail_reason] = mapped_reason if mapped_reason
    end

    if self.datastore['RHOST'] && (self.options['RHOST'] || self.options['RHOSTS'])
      # Only include RHOST if it's a single valid host, not a multi-value string or file path
      rhost = self.datastore['RHOST'].to_s
      # Check if RHOST is a valid IP address to avoid ActiveRecord issues on validation
      if Rex::Socket.is_ip_addr?(rhost)
        info[:host] = rhost
      end
    end

    if self.datastore['RPORT'] and self.options['RPORT']
      info[:port] = self.datastore['RPORT']
      if self.class.ancestors.include?(Msf::Exploit::Remote::Tcp)
        info[:proto] = 'tcp'
      elsif self.class.ancestors.include?(Msf::Exploit::Remote::Udp)
        info[:proto] = 'udp'
      end
    end

    # When the check identified a vulnerability, ensure the vuln record exists
    # before report_exploit_failure tries to look it up.  The UI-level
    # check_simple also calls report_vuln, but that happens *after* this
    # ensure block, so the vuln wouldn't exist yet for the attempt lookup.
    if info[:host] && self.respond_to?(:check_code) &&
       self.check_code.is_a?(Msf::Exploit::CheckCode) &&
       [Msf::Exploit::CheckCode::Vulnerable, Msf::Exploit::CheckCode::Appears].include?(self.check_code)
      vuln_info = if self.check_code == Msf::Exploit::CheckCode::Appears
        "Target appears vulnerable based on check of #{self.fullname}."
      else
        "Vulnerability confirmed by check of #{self.fullname}."
      end
      vuln_opts = {
        workspace: info[:workspace],
        host: info[:host],
        name: self.name,
        refs: self.references,
        info: vuln_info
      }
      # Include port so that checks against different ports on the same
      # host create distinct vuln records instead of collapsing into one.
      vuln_opts[:port] = info[:port] if info[:port]
      vuln_opts[:proto] = info[:proto] if info[:proto]
      framework.db.report_vuln(vuln_opts)
    end

    # Skip creating a duplicate vuln attempt if one was already recorded
    # during this run (e.g. by Auxiliary::Report#report_vuln).  When a
    # check_code is available, update the existing attempt so it carries the
    # check result details (the attempt created by report_vuln may not have
    # had the check_code yet because it runs before job_run_proc stores it).
    if self.respond_to?(:last_vuln_attempt) && self.last_vuln_attempt
      if self.respond_to?(:check_code) && self.check_code.is_a?(Msf::Exploit::CheckCode)
        _enrich_existing_vuln_attempt(info, self.last_vuln_attempt)
      end
      info[:skip_vuln_attempt] = true
    end

    framework.db.report_exploit_failure(info)
  end

  private

  # Update the VulnAttempt for this module/host with check code details that
  # were not available when report_vuln originally created it.
  #
  # @param info [Hash] enrichment data built by report_failure
  # @param recorded_attempt [Mdm::VulnAttempt, true] the attempt object stored
  #   by report_vuln, or +true+ if only the flag was propagated (legacy/fallback).
  def _enrich_existing_vuln_attempt(info, recorded_attempt = nil)
    return unless framework.db&.active

    # Use the stored attempt directly when available — avoids a racy
    # re-query that could match the wrong row under concurrency.
    attempt = recorded_attempt if recorded_attempt.is_a?(::Mdm::VulnAttempt)

    # Fallback: re-query if we only have the boolean flag (e.g. propagated
    # through a replicant that only forwarded +true+).
    if attempt.nil?
      host = info[:host]
      return unless host

      host_obj = if host.is_a?(::Mdm::Host)
                   host
                 else
                   wspace = info[:workspace] || framework.db.find_workspace(workspace)
                   framework.db.get_host(workspace: wspace, address: host.to_s)
                 end
      return unless host_obj

      scope = ::Mdm::VulnAttempt
                .joins(:vuln)
                .where(module: fullname, vulns: { host_id: host_obj.id })

      # Narrow by service attributes when available so we don't match an
      # attempt against a different service on the same host (e.g. port 80
      # vs 9200, or TCP vs UDP on the same port).
      if info[:port]
        service_conditions = { port: info[:port] }
        service_conditions[:proto] = info[:proto].to_s.downcase if info[:proto]

        scope = scope.joins(vuln: :service)
                     .where(services: service_conditions)
      end

      attempt = scope.order(attempted_at: :desc).first
    end

    return unless attempt

    updates = {}
    updates[:check_code] = info[:check_code] if info[:check_code] && attempt.check_code.blank?
    updates[:check_detail] = info[:check_detail] if info[:check_detail] && attempt.check_detail.blank?
    mapped_reason = Msf::Module::Failure.fail_reason_from_check_code(check_code)
    updates[:fail_reason] = mapped_reason if mapped_reason && attempt.fail_reason == 'Untried'
    # Clear the placeholder fail_detail set by report_vuln when we have a
    # real check result.
    updates[:fail_detail] = nil if updates[:fail_reason] && attempt.fail_detail == 'vulnerability identified'

    attempt.update(updates) if updates.any?
  rescue ::StandardError => e
    elog('Failed to enrich vuln attempt with check code', error: e)
  end
end
