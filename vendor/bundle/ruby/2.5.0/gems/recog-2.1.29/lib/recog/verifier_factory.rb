require 'recog/verifier'
require 'recog/formatter'
require 'recog/verify_reporter'

module Recog
module VerifierFactory
  def self.build(options)
    formatter = Formatter.new(options, $stdout)
    reporter  = VerifyReporter.new(options, formatter)
    Verifier.new(options.fingerprints, reporter)
  end
end
end
