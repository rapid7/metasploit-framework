require 'em_test_helper'

class TestIterator < Test::Unit::TestCase

  # By default, format the time with tenths-of-seconds.
  # Some tests should ask for extra decimal places to ensure
  # that delays between iterations will receive a changed time.
  def get_time(n=1)
    time = EM.current_time
    time.strftime('%H:%M:%S.') + time.tv_usec.to_s[0, n]
  end

  def test_default_concurrency
    items = {}
    list = 1..10
    EM.run {
      EM::Iterator.new(list).each( proc {|num,iter|
        time = get_time(3)
        items[time] ||= []
        items[time] << num
        EM::Timer.new(0.02) {iter.next}
      }, proc {EM.stop})
    }
    assert_equal(10, items.keys.size)
    assert_equal(list.to_a.sort, items.values.flatten.sort)
  end

  def test_default_concurrency_with_a_proc
    items = {}
    list = (1..10).to_a
    original_list = list.dup
    EM.run {
      EM::Iterator.new(proc{list.pop || EM::Iterator::Stop}).each( proc {|num,iter|
        time = get_time(3)
        items[time] ||= []
        items[time] << num
        EM::Timer.new(0.02) {iter.next}
      }, proc {EM.stop})
    }
    assert_equal(10, items.keys.size)
    assert_equal(original_list.to_a.sort, items.values.flatten.sort)
  end

  def test_concurrency_bigger_than_list_size
    items = {}
    list = [1,2,3]
    EM.run {
      EM::Iterator.new(list,10).each(proc {|num,iter|
        time = get_time
        items[time] ||= []
        items[time] << num
        EM::Timer.new(1) {iter.next}
      }, proc {EM.stop})
    }
    assert_equal(1, items.keys.size)
    assert_equal(list.to_a.sort, items.values.flatten.sort)
  end

  def test_changing_concurrency_affects_active_iteration
    items = {}
    list = 1..25
    seen = 0
    EM.run {
      i = EM::Iterator.new(list,1)
      i.each(proc {|num,iter|
        time = get_time
        items[time] ||= []
        items[time] << num
        if (seen += 1) == 5
          # The first 5 items will be distinct times
          # The next 20 items will happen in 2 bursts
          i.concurrency = 10
        end
        EM::Timer.new(0.2) {iter.next}
      }, proc {EM.stop})
    }
    assert_in_delta(7, items.keys.size, 1)
    assert_equal(list.to_a.sort, items.values.flatten.sort)
  end

  def test_map
    list = 100..150
    EM.run {
      EM::Iterator.new(list).map(proc{ |num,iter|
        EM.add_timer(0.01){ iter.return(num) }
      }, proc{ |results|
        assert_equal(list.to_a.size, results.size)
       EM.stop
      })
    }
  end

  def test_inject
    omit_if(windows?)

    list = %w[ pwd uptime uname date ]
    EM.run {
      EM::Iterator.new(list, 2).inject({}, proc{ |hash,cmd,iter|
        EM.system(cmd){ |output,status|
          hash[cmd] = status.exitstatus == 0 ? output.strip : nil
          iter.return(hash)
        }
      }, proc{ |results|
        assert_equal(results.keys.sort, list.sort)
        EM.stop
      })
    }
  end

  def test_concurrency_is_0
    EM.run {
      assert_raise ArgumentError do
        EM::Iterator.new(1..5,0)
      end
      EM.stop
    }
  end
end
