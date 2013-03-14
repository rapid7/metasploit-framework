#!/usr/bin/env rackup -s thin
# 
#  async_tailer.ru
#  raggi/thin
#
#  Tested with 150 spawned tails on OS X
#  
#  Created by James Tucker on 2008-06-18.
#  Copyright 2008 James Tucker <raggi@rubyforge.org>.

# Uncomment if appropriate for you..
# EM.epoll
# EM.kqueue

class DeferrableBody
  include EventMachine::Deferrable
  
  def initialize
    @queue = []
    # make sure to flush out the queue before closing the connection
    callback{
      until @queue.empty?
        @queue.shift.each{|chunk| @body_callback.call(chunk) }
      end
    }
  end
  
  def schedule_dequeue
    return unless @body_callback
    EventMachine::next_tick do
      next unless body = @queue.shift
      body.each do |chunk|
        @body_callback.call(chunk)
      end
      schedule_dequeue unless @queue.empty?
    end
  end 

  def call(body)
    @queue << body
    schedule_dequeue
  end

  def each &blk
    @body_callback = blk
    schedule_dequeue
  end

end

module TailRenderer
  attr_accessor :callback

  def receive_data(data)
    @callback.call([data])
  end

  def unbind
    @callback.succeed
  end
end

class AsyncTailer
  
  AsyncResponse = [-1, {}, []].freeze
    
  def call(env)
    
    body = DeferrableBody.new
    
    EventMachine::next_tick do
      
      env['async.callback'].call [200, {'Content-Type' => 'text/html'}, body]
      
      body.call ["<h1>Async Tailer</h1><pre>"]
      
    end
    
    EventMachine::popen('tail -f /var/log/system.log', TailRenderer) do |t|
      
      t.callback = body
      
      # If for some reason we 'complete' body, close the tail.
      body.callback do
        t.close_connection
      end
      
      # If for some reason the client disconnects, close the tail.
      body.errback do
        t.close_connection
      end
      
    end
    
    AsyncResponse
  end
  
end

run AsyncTailer.new
