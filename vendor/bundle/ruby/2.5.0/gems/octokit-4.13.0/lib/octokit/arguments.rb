module Octokit

  # Extracts options from method arguments
  # @private
  class Arguments < Array
    attr_reader :options

    def initialize(args)
      @options = args.last.is_a?(::Hash) ? args.pop : {}
      super(args)
    end

  end
end
