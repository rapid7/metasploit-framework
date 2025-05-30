#
# Linux ppc prepends
#
module Msf::Payload::Linux::Ppc64le::Prepends
  include Msf::Payload::Linux::Prepends

  def prepends_order
    %w[]
  end

  def appends_order
    %w[]
  end

  def prepends_map
    {
    }
  end

  def appends_map
    {
    }
  end
end
