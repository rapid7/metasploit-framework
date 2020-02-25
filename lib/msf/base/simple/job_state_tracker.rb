require 'monitor'

class JobStateTracker

  include MonitorMixin

  def initialize(result_ttl=nil)
    self.results_size = 0
    self.ready = Set.new
    self.running = Set.new
    # Can be expanded upon later to allow the option of a MemCacheStore being backed by redis for example
    self.results = ActiveSupport::Cache::MemoryStore.new(expires_in: result_ttl || 5.minutes)
  end

  def waiting(id)
    ready << id
  end

  def start(id)
    running << id
    ready.delete(id)
  end

  def completed(id, result, ttl=nil)
    begin
      # ttl of nil means it will take the default expiry time
      self.results_size += 1 if results.write(id, {result: result}, ttl)
    ensure
      running.delete(id)
    end
  end

  def failed(id, error, ttl=nil)
    begin
      # ttl of nil means it will take the default expiry time
      self.results_size += 1 if results.write(id, {error: error.to_s}, ttl)
    ensure
      running.delete(id)
    end
  end

  def running?(id)
    running.include? id
  end

  def waiting?(id)
    ready.include? id
  end

  def finished?(id)
    results.exist? id
  end

  def result(id)
    results.fetch(id)
  end

  def delete(id)
    result_deleted = results.delete(id)
    self.results_size -= 1 if result_deleted
    result_deleted
  end

  def waiting_size
    ready.size
  end

  def running_size
    running.size
  end

  alias :ack :delete

  attr_accessor :results_size

  private

  attr_writer :results_size
  attr_accessor :ready, :running, :results
end