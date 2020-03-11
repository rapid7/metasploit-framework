require 'singleton'

class NoopJobListener

  include Singleton

  def waiting(id)
  end

  def start(id)
  end

  def completed(id, result, mod)
  end

  def failed(id, error, mod)
  end

  def running?(id)
  end

  def waiting?(id)
  end

  def finished?(id)
  end

  def result(id)
  end

  def delete(id)
  end

  def results_size
  end

  def waiting_size
  end

  def running_size
  end

  alias :ack :delete
end