module EventMachine
  # A simple iterator for concurrent asynchronous work.
  #
  # Unlike ruby's built-in iterators, the end of the current iteration cycle is signaled manually,
  # instead of happening automatically after the yielded block finishes executing. For example:
  #
  #   (0..10).each{ |num| }
  #
  # becomes:
  #
  #   EM::Iterator.new(0..10).each{ |num,iter| iter.next }
  #
  # This is especially useful when doing asynchronous work via reactor libraries and
  # functions. For example, given a sync and async http api:
  #
  #   response = sync_http_get(url); ...
  #   async_http_get(url){ |response| ... }
  #
  # a synchronous iterator such as:
  #
  #   responses = urls.map{ |url| sync_http_get(url) }
  #   ...
  #   puts 'all done!'
  #
  # could be written as:
  #
  #   EM::Iterator.new(urls).map(proc{ |url,iter|
  #     async_http_get(url){ |res|
  #       iter.return(res)
  #     }
  #   }, proc{ |responses|
  #     ...
  #     puts 'all done!'
  #   })
  #
  # Now, you can take advantage of the asynchronous api to issue requests in parallel. For example,
  # to fetch 10 urls at a time, simply pass in a concurrency of 10:
  #
  #   EM::Iterator.new(urls, 10).each do |url,iter|
  #     async_http_get(url){ iter.next }
  #   end
  #
  class Iterator
    Stop = "EM::Stop"
    # Create a new parallel async iterator with specified concurrency.
    #
    #   i = EM::Iterator.new(1..100, 10)
    #
    # will create an iterator over the range that processes 10 items at a time. Iteration
    # is started via #each, #map or #inject
    #
    # The list may either be an array-like object, or a proc that returns a new object
    # to be processed each time it is called.  If a proc is used, it must return
    # EventMachine::Iterator::Stop to signal the end of the iterations.
    #
    def initialize(list, concurrency = 1)
      raise ArgumentError, 'concurrency must be bigger than zero' unless (concurrency > 0)
      if list.respond_to?(:call)
        @list = nil
        @list_proc = list
      elsif list.respond_to?(:to_a)
        @list = list.to_a.dup
        @list_proc = nil
      else
        raise ArgumentError, 'argument must be a proc or an array'
      end
      @concurrency = concurrency

      @started = false
      @ended = false
    end

    # Change the concurrency of this iterator. Workers will automatically be spawned or destroyed
    # to accomodate the new concurrency level.
    #
    def concurrency=(val)
      old = @concurrency
      @concurrency = val

      spawn_workers if val > old and @started and !@ended
    end
    attr_reader :concurrency

    # Iterate over a set of items using the specified block or proc.
    #
    #   EM::Iterator.new(1..100).each do |num, iter|
    #     puts num
    #     iter.next
    #   end
    #
    # An optional second proc is invoked after the iteration is complete.
    #
    #   EM::Iterator.new(1..100).each(
    #     proc{ |num,iter| iter.next },
    #     proc{ puts 'all done' }
    #   )
    #
    def each(foreach=nil, after=nil, &blk)
      raise ArgumentError, 'proc or block required for iteration' unless foreach ||= blk
      raise RuntimeError, 'cannot iterate over an iterator more than once' if @started or @ended

      @started = true
      @pending = 0
      @workers = 0

      all_done = proc{
        after.call if after and @ended and @pending == 0
      }

      @process_next = proc{
        # p [:process_next, :pending=, @pending, :workers=, @workers, :ended=, @ended, :concurrency=, @concurrency, :list=, @list]
        unless @ended or @workers > @concurrency
          item = next_item()
          if item.equal?(Stop)
            @ended = true
            @workers -= 1
            all_done.call
          else
            @pending += 1

            is_done = false
            on_done = proc{
              raise RuntimeError, 'already completed this iteration' if is_done
              is_done = true

              @pending -= 1

              if @ended
                all_done.call
              else
                EM.next_tick(@process_next)
              end
            }
            class << on_done
              alias :next :call
            end

            foreach.call(item, on_done)
          end
        else
          @workers -= 1
        end
      }

      spawn_workers

      self
    end

    # Collect the results of an asynchronous iteration into an array.
    #
    #   EM::Iterator.new(%w[ pwd uptime uname date ], 2).map(proc{ |cmd,iter|
    #     EM.system(cmd){ |output,status|
    #       iter.return(output)
    #     }
    #   }, proc{ |results|
    #     p results
    #   })
    #
    def map(foreach, after)
      index = 0

      inject([], proc{ |results,item,iter|
        i = index
        index += 1

        is_done = false
        on_done = proc{ |res|
          raise RuntimeError, 'already returned a value for this iteration' if is_done
          is_done = true

          results[i] = res
          iter.return(results)
        }
        class << on_done
          alias :return :call
          def next
            raise NoMethodError, 'must call #return on a map iterator'
          end
        end

        foreach.call(item, on_done)
      }, proc{ |results|
        after.call(results)
      })
    end

    # Inject the results of an asynchronous iteration onto a given object.
    #
    #   EM::Iterator.new(%w[ pwd uptime uname date ], 2).inject({}, proc{ |hash,cmd,iter|
    #     EM.system(cmd){ |output,status|
    #       hash[cmd] = status.exitstatus == 0 ? output.strip : nil
    #       iter.return(hash)
    #     }
    #   }, proc{ |results|
    #     p results
    #   })
    #
    def inject(obj, foreach, after)
      each(proc{ |item,iter|
        is_done = false
        on_done = proc{ |res|
          raise RuntimeError, 'already returned a value for this iteration' if is_done
          is_done = true

          obj = res
          iter.next
        }
        class << on_done
          alias :return :call
          def next
            raise NoMethodError, 'must call #return on an inject iterator'
          end
        end

        foreach.call(obj, item, on_done)
      }, proc{
        after.call(obj)
      })
    end

    private

    # Spawn workers to consume items from the iterator's enumerator based on the current concurrency level.
    #
    def spawn_workers
      EM.next_tick(start_worker = proc{
        if @workers < @concurrency and !@ended
          # p [:spawning_worker, :workers=, @workers, :concurrency=, @concurrency, :ended=, @ended]
          @workers += 1
          @process_next.call
          EM.next_tick(start_worker)
        end
      })
      nil
    end

    # Return the next item from @list or @list_proc.
    # Once items have run out, will return EM::Iterator::Stop.  Procs must supply this themselves
    def next_item
      if @list_proc
        @list_proc.call
      else
        @list.empty? ? Stop : @list.shift
      end
    end
  end
end

# TODO: pass in one object instead of two? .each{ |iter| puts iter.current; iter.next }
# TODO: support iter.pause/resume/stop/break/continue?
# TODO: create some exceptions instead of using RuntimeError
