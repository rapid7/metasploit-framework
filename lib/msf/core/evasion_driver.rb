# -*- coding: binary -*-
require 'msf/core'

module Msf

class EvasionDriver

  #
  # Initializes the evasion driver using the supplied framework instance.
  #
  def initialize(framework)
    self.payload                = nil
    self.evasion                = nil
    self.use_job                = false
    self.job_id                 = nil
    self.force_wait_for_session = false
    self.semaphore              = Mutex.new
  end

  def target_idx=(target_idx)
    if (target_idx)
      # Make sure the target index is valid
      if (target_idx >= evasion.targets.length)
        raise Rex::ArgumentError, "Invalid target index.", caller
      end
    end

     # Set the active target
    @target_idx = target_idx
  end

  def target_idx
    @target_idx
  end


  #
  # Checks to see if the supplied payload is compatible with the
  # current evasion module.  Assumes that target_idx is valid.
  #
  def compatible_payload?(payload)
    evasion_platform = evasion.targets[target_idx].platform || evasion.platform
    return ((payload.platform & evasion_platform).empty? == false)
  end

  def validate
    if (payload == nil)
      raise MissingPayloadError, "A payload has not been selected.", caller
    end

    # Make sure the payload is compatible after all
    if (compatible_payload?(payload) == false)
      raise IncompatiblePayloadError.new(payload.refname), "Incompatible payload", caller
    end

    # Associate the payload instance with the evasion
    payload.assoc_exploit = evasion

    # Finally, validate options on the evasion module to ensure that things
    # are ready to operate as they should.
    evasion.options.validate(evasion.datastore)

    # Validate the payload's options.  The payload's datastore is
    # most likely shared against the evasion's datastore, but in case it
    # isn't.
    payload.options.validate(payload.datastore)

    return true
  end

  def run
    # First thing's first -- validate the state.  Make sure all requirement
    # parameters are set, including those that are derived from the
    # datastore.
    validate()

    # Explicitly clear the module's job_id in case it was set in a previous
    # run
    evasion.job_id = nil

    # Generate the encoded version of the supplied payload on the
    # evasion module instance
    evasion.generate_payload(payload)

    # No need to copy since we aren't creating a job.  We wait until
    # they're finished running to do anything else with them, so
    # nothing should be able to modify their datastore or other
    # settings until after they're done.
    ctx = [ evasion, payload ]

    job_run_proc(ctx)
    job_cleanup_proc(ctx)

  end

  attr_accessor :evasion # :nodoc:
  attr_accessor :payload # :nodoc:
  attr_accessor :use_job # :nodoc:
  #
  # The identifier of the job this evasion module is launched as, if it's run as a
  # job.
  #
  attr_accessor :job_id
  attr_accessor :force_wait_for_session # :nodoc:
  attr_accessor :session # :nodoc:

  # To synchronize threads cleaning up the evasion
  attr_accessor :semaphore

protected

  #
  # Job run proc, sets up the eevasion and kicks it off.
  #
  def job_run_proc(ctx)
    evasion, payload = ctx
    evasion.setup
    evasion.framework.events.on_module_run(evasion)

    # Launch the evasion module
    evasion.run
  end

  #
  # Clean up the evasion after the job completes.
  #
  def job_cleanup_proc(ctx)
    evasion, payload = ctx
    evasion.framework.events.on_module_complete(evasion)
    semaphore.synchronize { evasion.cleanup }
  end

end

end

