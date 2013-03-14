class FakeFramework < Spork::TestFramework
  include Spork::TestIOStreams

  attr_accessor :wait_time
  DEFAULT_PORT = 1000

  def self.helper_file
    SPEC_TMP_DIR + "/fake/test_helper.rb"
  end

  def run_tests(argv, input, output)
    sleep(@wait_time || 0.5)
    true
  end
end
