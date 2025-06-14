# -*- coding: binary -*-
module Rex
module Ui
module Text

###
#
# This class wraps the creation of an IRB shell.
#
###
class IrbShell

  @@IrbInitialized = false

  def initialize(binding)
    @binding_ctx = binding
  end

  #
  # Runs the IRB shell until completion.  The binding parameter initializes
  # IRB to the appropriate binding context.
  #
  def run
    # Initialize IRB by setting up its internal configuration hash and
    # stuff.
    if (@@IrbInitialized == false)
      require 'irb'

      IRB.setup(nil)
      IRB.conf[:PROMPT_MODE]  = :SIMPLE

      @@IrbInitialized = true
    end

    # Create a new IRB instance
    irb = IRB::Irb.new(IRB::WorkSpace.new(@binding_ctx))

    # Set the primary irb context so that exit and other intrinsic
    # commands will work.
    IRB.conf[:MAIN_CONTEXT] = irb.context

    # Trap interrupt
    begin
      old_sigint = trap("SIGINT") do
        irb.signal_handle
      end

      # Keep processing input until the cows come home...
      catch(:IRB_EXIT) do
        irb.eval_input
      end
    ensure
      trap("SIGINT", old_sigint) if old_sigint
    end
  end

end
end
end
end
