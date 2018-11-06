class Pry

  # As a REPL, we often want to catch any unexpected exceptions that may have
  # been raised; however we don't want to go overboard and prevent the user
  # from exiting Pry when they want to.
  module RescuableException
    def self.===(exception)
      case exception
        # Catch when the user hits ^C (Interrupt < SignalException), and assume
        # that they just wanted to stop the in-progress command (just like bash
        # etc.)
      when Interrupt
        true
        # Don't catch signals (particularly not SIGTERM) as these are unlikely
        # to be intended for pry itself. We should also make sure that
        # Kernel#exit works.
      when *Pry.config.exception_whitelist
        false
        # All other exceptions will be caught.
      else
        true
      end
    end
  end

  # Catches SecurityErrors if $SAFE is set
  module Pry::TooSafeException
    def self.===(exception)
      $SAFE > 0 && SecurityError === exception
    end
  end

  # An Exception Tag (cf. Exceptional Ruby) that instructs Pry to show the error
  # in a more user-friendly manner. This should be used when the exception
  # happens within Pry itself as a direct consequence of the user typing
  # something wrong.
  #
  # This allows us to distinguish between the user typing:
  #
  # pry(main)> def )
  # SyntaxError: unexpected )
  #
  # pry(main)> method_that_evals("def )")
  # SyntaxError: (eval):1: syntax error, unexpected ')'
  # from ./a.rb:2 in `eval'
  module UserError; end

  # When we try to get a binding for an object, we try to define a method on
  # that Object's singleton class. This doesn't work for "frozen" Object's, and
  # the exception is just a vanilla RuntimeError.
  module FrozenObjectException
    def self.===(exception)
      ["can't modify frozen class/module",
       "can't modify frozen Class",
       "can't modify frozen object",
      ].include?(exception.message)
    end
  end

  # Don't catch these exceptions
  DEFAULT_EXCEPTION_WHITELIST = [SystemExit,
                                 SignalException,
                                 Pry::TooSafeException]

  # CommandErrors are caught by the REPL loop and displayed to the user. They
  # indicate an exceptional condition that's fatal to the current command.
  class CommandError < StandardError; end
  class MethodNotFound < CommandError; end

  # indicates obsolete API
  class ObsoleteError < StandardError; end

  # This is to keep from breaking under Rails 3.2 for people who are doing that
  # IRB = Pry thing.
  module ExtendCommandBundle
  end

end
