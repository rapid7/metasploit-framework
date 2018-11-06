require 'net/ssh/loggable'
require 'net/ssh/ruby_compat'

module Net 
  module SSH 
    module Connection
      # EventLoop can be shared across multiple sessions
      #
      # one issue is with blocks passed to loop, etc.
      # they should get current session as parameter, but in
      # case you're using multiple sessions in an event loop it doesnt makes sense
      # and we don't pass session.
      class EventLoop
        include Loggable
    
        def initialize(logger=nil)
          self.logger = logger
          @sessions = []
        end
    
        def register(session)
          @sessions << session
        end
    
        # process until timeout
        # if a block is given a session will be removed from loop
        # if block returns false for that session
        def process(wait = nil, &block)
          return false unless ev_preprocess(&block)
    
          ev_select_and_postprocess(wait)
        end
    
        # process the event loop but only for the sepcified session
        def process_only(session, wait = nil)
          orig_sessions = @sessions
          begin
            @sessions = [session]
            return false unless ev_preprocess
            ev_select_and_postprocess(wait)
          ensure
            @sessions = orig_sessions
          end
        end
    
        # Call preprocess on each session. If block given and that
        # block retuns false then we exit the processing
        def ev_preprocess(&block)
          return false if block_given? && !yield(self)
          @sessions.each(&:ev_preprocess)
          return false if block_given? && !yield(self)
          return true
        end
    
        def ev_select_and_postprocess(wait)
          owners = {}
          r = []
          w = []
          minwait = nil
          @sessions.each do |session|
            sr,sw,actwait = session.ev_do_calculate_rw_wait(wait)
            minwait = actwait if actwait && (minwait.nil? || actwait < minwait)
            r.push(*sr)
            w.push(*sw)
            sr.each { |ri| owners[ri] = session }
            sw.each { |wi| owners[wi] = session }
          end
    
          readers, writers, = IO.select(r, w, nil, minwait)
    
          fired_sessions = {}
    
          if readers
            readers.each do |reader|
              session = owners[reader]
              (fired_sessions[session] ||= { r: [],w: [] })[:r] << reader
            end
          end
          if writers
            writers.each do |writer|
              session = owners[writer]
              (fired_sessions[session] ||= { r: [],w: [] })[:w] << writer
            end
          end
    
          fired_sessions.each do |s,rw|
            s.ev_do_handle_events(rw[:r],rw[:w])
          end
    
          @sessions.each { |s| s.ev_do_postprocess(fired_sessions.key?(s)) }
          true
        end
      end

      # optimized version for a single session
      class SingleSessionEventLoop < EventLoop
        # Compatibility for original single session event loops:
        # we call block with session as argument
        def ev_preprocess(&block)
          return false if block_given? && !yield(@sessions.first)
          @sessions.each(&:ev_preprocess)
          return false if block_given? && !yield(@sessions.first)
          return true
        end
    
        def ev_select_and_postprocess(wait)
          raise "Only one session expected" unless @sessions.count == 1
          session = @sessions.first
          sr,sw,actwait = session.ev_do_calculate_rw_wait(wait)
          readers, writers, = IO.select(sr, sw, nil, actwait)
    
          session.ev_do_handle_events(readers,writers)
          session.ev_do_postprocess(!((readers.nil? || readers.empty?) && (writers.nil? || writers.empty?)))
        end
      end
    end
  end
end
