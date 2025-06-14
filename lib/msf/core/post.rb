# -*- coding: binary -*-

#
# A Post-exploitation module
#
class Msf::Post < Msf::Module

  class Complete < RuntimeError
  end

  class Failed < RuntimeError
  end

  include Msf::PostMixin

  # file_dropper sets needs_cleanup to true to track exploits that upload files
  # some post modules also use file_dropper, so let's define it here
  attr_accessor :needs_cleanup

  def setup
    m = replicant

    if m.actions.length > 0 && !m.action
      raise Msf::MissingActionError, "Please use: #{m.actions.collect {|e| e.name} * ", "}"
    end

    # Msf::Module(Msf::PostMixin)#setup
    super
  end

  def type
    Msf::MODULE_POST
  end

  def self.type
    Msf::MODULE_POST
  end

  #
  # Create an anonymous module not tied to a file.  Only useful for IRB.
  #
  def self.create(session)
    mod = new
    mod.instance_variable_set(:@session, session)
    # Have to override inspect because for whatever reason, +type+ is coming
    # from the wrong scope and i can't figure out how to fix it.
    mod.instance_eval do
      def inspect
        "#<Msf::Post anonymous>"
      end
    end
    mod.class.refname = "anonymous"

    mod
  end

  # This method returns the ID of the Mdm::Session that the post module
  # is currently running against.
  #
  # @return [NilClass] if there is no database record for the session
  # @return [Integer] if there is a database record to get the id for
  def session_db_id
    if session.db_record
      session.db_record.id
    else
      nil
    end
  end

  # Override Msf::Module#fail_with for Msf::Simple::Post::job_run_proc
  def fail_with(reason, msg = nil)
    raise Msf::Post::Failed, "#{reason.to_s}: #{msg}"
  end

end
