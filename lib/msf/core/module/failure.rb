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

    if self.datastore['RHOST'] && (self.options['RHOST'] || self.options['RHOSTS'])
      info[:host] = self.datastore['RHOST']
    end

    if self.datastore['RPORT'] and self.options['RPORT']
      info[:port] = self.datastore['RPORT']
      if self.class.ancestors.include?(Msf::Exploit::Remote::Tcp)
        info[:proto] = 'tcp'
      end
    end

    framework.db.report_exploit_failure(info)
  end

end
