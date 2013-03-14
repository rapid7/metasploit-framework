require 'em/completion'

class TestCompletion < Test::Unit::TestCase
  def completion
    @completion ||= EM::Completion.new
  end

  def crank
    # This is a slow solution, but this just executes the next tick queue
    # once. It's the easiest way for now.
    EM.run { EM.stop }
  end

  def results
    @results ||= []
  end

  def test_state
    assert_equal :unknown, completion.state
  end

  def test_succeed
    completion.callback { |val| results << val }
    completion.succeed :object
    crank
    assert_equal :succeeded, completion.state
    assert_equal [:object], results
  end

  def test_fail
    completion.errback { |val| results << val }
    completion.fail :object
    crank
    assert_equal :failed, completion.state
    assert_equal [:object], results
  end

  def test_callback
    completion.callback { results << :callback }
    completion.errback  { results << :errback  }
    completion.succeed
    crank
    assert_equal [:callback], results
  end

  def test_errback
    completion.callback { results << :callback }
    completion.errback  { results << :errback  }
    completion.fail
    crank
    assert_equal [:errback], results
  end

  def test_stateback
    completion.stateback(:magic) { results << :stateback }
    completion.change_state(:magic)
    crank
    assert_equal [:stateback], results
  end

  def test_does_not_enqueue_when_completed
    completion.callback { results << :callback }
    completion.succeed
    completion.errback  { results << :errback  }
    completion.fail
    crank
    assert_equal [:callback], results
  end

  def test_completed
    assert_equal false, completion.completed?
    completion.succeed
    assert_equal true, completion.completed?
    completion.fail
    assert_equal true, completion.completed?
    completion.change_state :magic
    assert_equal false, completion.completed?
  end

  def test_recursive_callbacks
    completion.callback do |val|
      results << val
      completion.succeed :two
    end
    completion.callback do |val|
      results << val
      completion.succeed :three
    end
    completion.callback do |val|
      results << val
    end
    completion.succeed :one
    crank
    assert_equal [:one, :two, :three], results
  end

  def test_late_defined_callbacks
    completion.callback { results << :one }
    completion.succeed
    crank
    assert_equal [:one], results
    completion.callback { results << :two }
    crank
    assert_equal [:one, :two], results
  end

  def test_cleared_completions
    completion.callback { results << :callback }
    completion.errback  { results << :errback  }

    completion.succeed
    crank
    completion.fail
    crank
    completion.succeed
    crank

    assert_equal [:callback], results
  end

  def test_skip_completed_callbacks
    completion.callback { results << :callback }
    completion.succeed
    crank

    completion.errback  { results << :errback  }
    completion.fail
    crank

    assert_equal [:callback], results
  end

  def test_completions
    completion.completion { results << :completion }
    completion.succeed
    crank
    assert_equal [:completion], results

    completion.change_state(:unknown)
    results.clear

    completion.completion { results << :completion }
    completion.fail
    crank
    assert_equal [:completion], results
  end

  def test_latent_completion
    completion.completion { results << :completion }
    completion.succeed
    crank
    completion.completion { results << :completion }
    crank
    assert_equal [:completion, :completion], results
  end

  def test_timeout
    args = [1, 2, 3]
    EM.run do
      completion.timeout(0.0001, *args)
      completion.errback { |*errargs| results << errargs }
      completion.completion { EM.stop }
      EM.add_timer(0.1) { flunk 'test timed out' }
    end
    assert_equal [[1,2,3]], results
  end

  def test_timeout_gets_cancelled
    EM.run do
      completion.timeout(0.0001, :timeout)
      completion.errback  { results << :errback  }
      completion.succeed
      EM.add_timer(0.0002) { EM.stop }
    end
    assert_equal [], results
  end
end
