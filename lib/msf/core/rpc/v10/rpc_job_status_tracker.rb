require 'monitor'

class RpcJobStatusTracker

  include MonitorMixin

  def initialize(result_ttl=nil)
    self.ready = Set.new
    self.running = Set.new
    # Can be expanded upon later to allow the option of a MemCacheStore being backed by redis for example
    self.results = ResultsMemoryStore.new(expires_in: result_ttl || 5.minutes)
  end

  def waiting(id)
    ready << id
  end

  def start(id)
    running << id
    ready.delete(id)
  end

  def completed(id, result, ttl=nil)
    add_result(id, {result: result}, ttl)
  end

  def failed(id, error, ttl=nil)
    add_result( id,{error: error.to_s}, ttl)
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
    results.delete(id)
  end

  def results_size
    results.size
  end

  def waiting_size
    ready.size
  end

  def running_size
    running.size
  end

  alias :ack :delete

  private

  def add_result(id, result, ttl=nil)
    begin
      # ttl of nil means it will take the default expiry time
      results.write(id, result, ttl)
    rescue Exception => e
      print_error("Job with id: #{id} finished but the result could not be stored")
      print_error("#{e.class}, #{e.message}")
      add_fallback_result(id, ttl)
    ensure
      running.delete(id)
    end
  end

  def add_fallback_result(id, ttl)
    begin
      vprint_debug("Writing fallback result to cache for Job id: #{id}")
      results.write(id, {unexpected_error: 'Job finished but the result could not be stored'}, ttl)
    rescue Exception => e
      print_error("Job with id: #{id} fallback result failed to be stored")
      print_error("#{e.class}, #{e.message}")
    end
  end

  attr_accessor :ready, :running, :results

  class ResultsMemoryStore < ActiveSupport::Cache::MemoryStore
    def size
      @data.size
    end
  end
end
