#
# Linux mipsle prepends
#
module Msf::Payload::Linux::Mipsle::Prepends
  include Msf::Payload::Linux::Prepends

  def prepends_order
    %w[]
  end

  def appends_order
    %w[]
  end

  def prepends_map
    {}
  end

  def appends_map
    {}
  end
end
