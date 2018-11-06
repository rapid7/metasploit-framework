require File.expand_path('../helper', __FILE__)

class ExtensionsTest < Minitest::Test
  module FooExtensions
    def foo
    end

    private
      def im_hiding_in_ur_foos
      end
  end

  module BarExtensions
    def bar
    end
  end

  module BazExtensions
    def baz
    end
  end

  module QuuxExtensions
    def quux
    end
  end

  module PainExtensions
    def foo=(name); end
    def bar?(name); end
    def fizz!(name); end
  end

  it 'will add the methods to the DSL for the class in which you register them and its subclasses' do
    Sinatra::Base.register FooExtensions
    assert Sinatra::Base.respond_to?(:foo)

    Sinatra::Application.register BarExtensions
    assert Sinatra::Application.respond_to?(:bar)
    assert Sinatra::Application.respond_to?(:foo)
    assert !Sinatra::Base.respond_to?(:bar)
  end

  it 'allows extending by passing a block' do
    Sinatra::Base.register { def im_in_ur_anonymous_module; end }
    assert Sinatra::Base.respond_to?(:im_in_ur_anonymous_module)
  end

  it 'will make sure any public methods added via Application#register are delegated to Sinatra::Delegator' do
    Sinatra::Application.register FooExtensions
    assert Sinatra::Delegator.private_instance_methods.
      map { |m| m.to_sym }.include?(:foo)
    assert !Sinatra::Delegator.private_instance_methods.
      map { |m| m.to_sym }.include?(:im_hiding_in_ur_foos)
  end

  it 'will handle special method names' do
    Sinatra::Application.register PainExtensions
    assert Sinatra::Delegator.private_instance_methods.
      map { |m| m.to_sym }.include?(:foo=)
    assert Sinatra::Delegator.private_instance_methods.
      map { |m| m.to_sym }.include?(:bar?)
    assert Sinatra::Delegator.private_instance_methods.
      map { |m| m.to_sym }.include?(:fizz!)
  end

  it 'will not delegate methods on Base#register' do
    Sinatra::Base.register QuuxExtensions
    assert !Sinatra::Delegator.private_instance_methods.include?("quux")
  end

  it 'will extend the Sinatra::Application application by default' do
    Sinatra.register BazExtensions
    assert !Sinatra::Base.respond_to?(:baz)
    assert Sinatra::Application.respond_to?(:baz)
  end

  module BizzleExtension
    def bizzle
      bizzle_option
    end

    def self.registered(base)
      fail "base should be BizzleApp" unless base == BizzleApp
      fail "base should have already extended BizzleExtension" unless base.respond_to?(:bizzle)
      base.set :bizzle_option, 'bizzle!'
    end
  end

  class BizzleApp < Sinatra::Base
  end

  it 'sends .registered to the extension module after extending the class' do
    BizzleApp.register BizzleExtension
    assert_equal 'bizzle!', BizzleApp.bizzle_option
    assert_equal 'bizzle!', BizzleApp.bizzle
  end
end
