module Msf::DBManager::Sink
  #
  # Attributes
  #

  # Stores a TaskManager for serializing database events
  attr_accessor :sink

  #
  # Instance Methods
  #

  #
  # Create a new database sink and initialize it
  #
  def initialize_sink
    self.sink = Msf::TaskManager.new(framework)
    self.sink.start
  end

  #
  # Add a new task to the sink
  #
  def queue(proc)
    self.sink.queue_proc(proc)
  end

  #
  # Wait for all pending write to finish
  #
  def sync
    # There is no more queue.
  end
end