require 'test_helper'

class WackyUserSession < Authlogic::Session::Base
  attr_accessor :counter
  authenticate_with User

  def initialize
    @counter = 0
    super
  end

  def persist_by_false
    self.counter += 1
    return false
  end

  def persist_by_true
    self.counter += 1
    return true
  end
end

module SessionTest
  class CallbacksTest < ActiveSupport::TestCase
    def setup
     WackyUserSession.reset_callbacks(:persist)
    end
    
    def test_no_callbacks
      assert_equal [], WackyUserSession._persist_callbacks.map(&:filter)
      session = WackyUserSession.new
      session.send(:persist)
      assert_equal 0, session.counter
    end

    def test_true_callback_cancelling_later_callbacks
      WackyUserSession.persist :persist_by_true, :persist_by_false
      assert_equal [:persist_by_true, :persist_by_false], WackyUserSession._persist_callbacks.map(&:filter)
  
      session = WackyUserSession.new
      session.send(:persist)
      assert_equal 1, session.counter
    end
  
    def test_false_callback_continuing_to_later_callbacks
      WackyUserSession.persist :persist_by_false, :persist_by_true
      assert_equal [:persist_by_false, :persist_by_true], WackyUserSession._persist_callbacks.map(&:filter)
  
      session = WackyUserSession.new
      session.send(:persist)
      assert_equal 2, session.counter
    end
  end
end