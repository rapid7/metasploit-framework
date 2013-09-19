# -*- coding: binary -*-
module Msf

require 'rex/payloads/win32/kernel'

module Exploit::KernelMode

  #
  # The way that the kernel-mode mixin works is by replacing the payload
  # to be encoded with one that encapsulates the kernel-mode payload as
  # well.
  #
  def encode_begin(real_payload, reqs)
    super

    reqs['EncapsulationRoutine'] = Proc.new { |reqs_, raw|
      encapsulate_kernel_payload(reqs_, raw)
    }
  end

  #
  # Increase the default delay by five seconds since some kernel-mode
  # payloads may not run immediately.
  #
  def wfs_delay
    super + 5
  end

protected

  #
  # Encapsulates the supplied raw payload within a kernel-mode payload.
  #
  def encapsulate_kernel_payload(reqs, raw)
    new_raw = nil
    ext_opt = reqs['ExtendedOptions'] || {}

    # Prepend and append any buffers that were specified in the extended
    # options.  This can be used do perform stack adjustments and other
    # such things against the user-mode payload rather than the
    # encapsulating payload.
    raw =
      (ext_opt['PrependUser'] || '') +
      raw +
      (ext_opt['AppendUser'] || '')

    # If this is a win32 target platform, try to encapsulate it in a
    # win32 kernel-mode payload.
    if target_platform.supports?(Msf::Module::PlatformList.win32)
      ext_opt['UserModeStub'] = raw

      new_raw = Rex::Payloads::Win32::Kernel.construct(ext_opt)
    end

    # If we did not generate a new payload, then something broke.
    if new_raw.nil?
      raise RuntimeError, "Could not encapsulate payload in kernel-mode payload"
    else
      dlog("Encapsulated user-mode payload size #{raw.length} in kernel-mode payload size #{new_raw.length}", 'core', LEV_1)
    end

    new_raw
  end

end

end
