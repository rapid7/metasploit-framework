require 'em_test_helper'

class TestResolver < Test::Unit::TestCase
  def test_nameserver
    assert_kind_of(String, EM::DNS::Resolver.nameserver)
  end

  def test_nameservers
    assert_kind_of(Array, EM::DNS::Resolver.nameservers)
  end

  def test_hosts
    assert_kind_of(Hash, EM::DNS::Resolver.hosts)

    # Make sure that blank or comment lines are skipped
    refute(EM::DNS::Resolver.hosts.include? nil)
  end

  def test_a
    pend('FIXME: this test is broken on Windows') if windows?

    EM.run {
      d = EM::DNS::Resolver.resolve "example.com"
      d.errback { assert false }
      d.callback { |r|
        assert r
        EM.stop
      }
    }
  end

  def test_bad_host
    EM.run {
      d = EM::DNS::Resolver.resolve "asdfasasdf"
      d.callback { assert false }
      d.errback  { assert true; EM.stop }
    }
  end

  def test_garbage
    assert_raises( ArgumentError ) {
      EM.run {
        EM::DNS::Resolver.resolve 123
      }
    }
  end

  # There isn't a public DNS entry like 'example.com' with an A rrset
  def test_a_pair
    pend('FIXME: this test is broken on Windows') if windows?

    EM.run {
      d = EM::DNS::Resolver.resolve "yahoo.com"
      d.errback { |err| assert false, "failed to resolve yahoo.com: #{err}" }
      d.callback { |r|
        assert_kind_of(Array, r)
        assert r.size > 1, "returned #{r.size} results: #{r.inspect}"
        EM.stop
      }
    }
  end

  def test_localhost
    pend('FIXME: this test is broken on Windows') if windows?

    EM.run {
      d = EM::DNS::Resolver.resolve "localhost"
      d.errback { assert false }
      d.callback { |r|
        assert_include(["127.0.0.1", "::1"], r.first)
        assert_kind_of(Array, r)

        EM.stop
      }
    }
  end

  def test_timer_cleanup
    pend('FIXME: this test is broken on Windows') if windows?

    EM.run {
      d = EM::DNS::Resolver.resolve "example.com"
      d.errback { |err| assert false, "failed to resolve example.com: #{err}" }
      d.callback { |r|
        # This isn't a great test, but it's hard to get more canonical
        # confirmation that the timer is cancelled
        assert_nil(EM::DNS::Resolver.socket.instance_variable_get(:@timer))

        EM.stop
      }
    }
  end

  def test_failure_timer_cleanup
    EM.run {
      d = EM::DNS::Resolver.resolve "asdfasdf"
      d.callback { assert false }
      d.errback {
        assert_nil(EM::DNS::Resolver.socket.instance_variable_get(:@timer))

        EM.stop
      }
    }
  end
end
