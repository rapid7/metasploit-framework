require_relative "test_helper"
require "time"

class TestTimecopWithoutDateButWithTime < Minitest::Test
  def test_loads_properly_when_time_is_required_instead_of_date
    require 'timecop'
  end
end
