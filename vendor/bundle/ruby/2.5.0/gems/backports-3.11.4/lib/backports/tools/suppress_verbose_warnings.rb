module Backports
  def self.suppress_verbose_warnings
    before = $VERBOSE
    $VERBOSE = false if $VERBOSE # Set to false (default warning) but not nil (no warnings)
    yield
  ensure
    $VERBOSE = before
  end
end
