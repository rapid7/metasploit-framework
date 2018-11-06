module Octokit

  # Allows warnings to be suppressed via environment variable.
  module Warnable

    # Wrapper around Kernel#warn to print warnings unless
    # OCTOKIT_SILENT is set to true.
    #
    # @return [nil]
    def octokit_warn(*message)
      unless ENV['OCTOKIT_SILENT']
        warn message
      end
    end
  end
end

