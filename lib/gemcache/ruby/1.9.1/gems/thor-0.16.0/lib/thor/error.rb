class Thor
  # Thor::Error is raised when it's caused by wrong usage of thor classes. Those
  # errors have their backtrace suppressed and are nicely shown to the user.
  #
  # Errors that are caused by the developer, like declaring a method which
  # overwrites a thor keyword, it SHOULD NOT raise a Thor::Error. This way, we
  # ensure that developer errors are shown with full backtrace.
  #
  class Error < StandardError
  end

  # Raised when a task was not found.
  #
  class UndefinedTaskError < Error
  end

  # Raised when a task was found, but not invoked properly.
  #
  class InvocationError < Error
  end

  class UnknownArgumentError < Error
  end

  class RequiredArgumentMissingError < InvocationError
  end

  class MalformattedArgumentError < InvocationError
  end

  # Raised when a user tries to call a private method encoded in templated filename.
  #
  class PrivateMethodEncodedError < Error
  end
end
