class Rex::Parser::ParsedResult

  attr_accessor :host_ids

  def initialize
    @host_ids = []
  end

  def record_host(host)
    @host_ids << host.id
  end

end
