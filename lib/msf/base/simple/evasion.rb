# -*- coding: binary -*-
require 'msf/base'

module Msf
module Simple

module Evasion

  include Module

  def self.run_simple(oevasion, opts, &block)
    evasion = oevasion.replicant
    # Trap and print errors here (makes them UI-independent)
    begin
      # Clone the module to prevent changes to the original instance

      Msf::Simple::Framework.simplify_module( evasion, false )
      yield(evasion) if block_given?

      # Import options from the OptionStr or Option hash.
      evasion._import_extra_options(opts)

      # Make sure parameters are valid.
      if (opts['Payload'] == nil)
        raise MissingPayloadError.new, caller
      end

      # Verify the options
      evasion.options.validate(evasion.datastore)

      # Start it up
      driver = EvasionDriver.new(evasion.framework)

      # Initialize the driver instance
      driver.evasion = evasion
      driver.payload = evasion.framework.payloads.create(opts['Payload'])

      # Was the payload valid?
      if (driver.payload == nil)
        raise MissingPayloadError,
          "You specified an invalid payload: #{opts['Payload']}", caller
      end

      # Use the supplied encoder, if any.  If one was not specified, then
      # nil will be assigned causing the evasion to default to picking the
      # best encoder.
      evasion.datastore['ENCODER'] = opts['Encoder'] if opts['Encoder']

      # Use the supplied NOP generator, if any.  If one was not specified, then
      # nil will be assigned causing the evasion to default to picking a
      # compatible NOP generator.
      evasion.datastore['NOP'] = opts['Nop'] if opts['Nop']

      # Force the payload to share the evasion's datastore
      driver.payload.share_datastore(driver.evasion.datastore)

      # Verify the payload options
      driver.payload.options.validate(driver.payload.datastore)

      # Set the target and then work some magic to derive index
      evasion.datastore['TARGET'] = opts['Target'] if opts['Target']
      target_idx = evasion.target_index

      if (target_idx == nil or target_idx < 0)
        raise MissingTargetError,
          "You must select a target.", caller
      end

      driver.target_idx = target_idx

      # Set the payload and evasion's subscriber values
      if ! opts['Quiet']
        driver.evasion.init_ui(opts['LocalInput'] || evasion.user_input, opts['LocalOutput'] || evasion.user_output)
        driver.payload.init_ui(opts['LocalInput'] || evasion.user_input, opts['LocalOutput'] || evasion.user_output)
      else
        driver.evasion.init_ui(nil, nil)
        driver.payload.init_ui(nil, nil)
      end

      if (opts['RunAsJob'])
        driver.use_job = true
      end

      # Let's rock this party
      driver.run

      # Save the job identifier this evasion is running as
      evasion.job_id  = driver.job_id

      # Propagate this back to the caller for console mgmt
      oevasion.job_id = evasion.job_id
    rescue ::Interrupt
      evasion.error = $!
      raise $!
    rescue ::Exception => e
      evasion.error = e
      evasion.print_error("evasion failed: #{e}")
      elog("Evasion failed (#{evasion.refname}): #{e}", 'core', LEV_0)
      dlog("Call stack:\n#{e.backtrace.join("\n")}", 'core', LEV_3)
    end

    nil
  end

  def run_simple(opts, &block)
    Msf::Simple::Evasion.run_simple(self, opts, &block)
  end

end

end
end

