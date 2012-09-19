############################################################################
# test_win32_api_callback.rb
# 
# Test case for the Win32::API::Callback class. You should run this as Rake
# task, i.e. 'rake test', instead of running it directly.
############################################################################
require 'rubygems'
gem 'test-unit'

require 'win32/api'
require 'test/unit'
include Win32

class TC_Win32_API_Callback < Test::Unit::TestCase
  def setup
    @buffer   = 0.chr * 260
    @api_ew   = API.new('EnumWindows', 'KP', 'L', 'user32')
    @api_gwt  = API.new('GetWindowText', 'LPI', 'I', 'user32')
    @callback = nil
  end
   
  def test_constructor
    assert_respond_to(API::Callback, :new)
    assert_nothing_raised{ API::Callback.new('LP', 'I') }
    assert_nothing_raised{ API::Callback.new('LP', 'I'){} }
  end
   
  def test_prototype
    assert_nothing_raised{ @callback = API::Callback.new('LP', 'I') }
    assert_respond_to(@callback, :prototype)
    assert_equal('LP', @callback.prototype)
  end
   
  def test_return_value
    assert_nothing_raised{ @callback = API::Callback.new('LP', 'I') }
    assert_respond_to(@callback, :return_type)
    assert_equal('I', @callback.return_type)
  end

  def test_address
    assert_nothing_raised{ @callback = API::Callback.new('LP', 'I') }
    assert_respond_to(@callback, :address)
    assert_kind_of(Integer, @callback.address)
    assert_true(@callback.address > 0)
  end
   
  def test_callback
    assert_nothing_raised{
      @callback = API::Callback.new('LP', 'I'){ |handle, param|
       	buf = "\0" * 200
        @api_gwt.call(handle, buf, 200);
        buf.index(param).nil? ? true : false           
      }
    }
    assert_nothing_raised{ @api_ew.call(@callback, 'UEDIT32') }
  end
   
  def test_constructor_expected_errors
    assert_raise(API::PrototypeError){ API::Callback.new('X') }
    assert_raise(API::PrototypeError){ API::Callback.new('L', 'Y') }
  end

  def test_constructor_expected_error_messages
    assert_raise_message("Illegal prototype 'X'"){ API::Callback.new('X') }
    assert_raise_message("Illegal return type 'Y'"){ API::Callback.new('L', 'Y') }
  end

  def teardown
    @buffer   = nil
    @api_ew   = nil
    @api_gwt  = nil
    @callback = nil
  end
end
