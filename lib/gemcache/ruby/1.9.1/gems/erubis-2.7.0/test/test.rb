##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##


unless defined?(TESTDIR)
  TESTDIR = File.dirname(__FILE__)
  LIBDIR  = TESTDIR == '.' ? '../lib' : File.dirname(TESTDIR) + '/lib'
  $: << TESTDIR
  $: << LIBDIR
end


require 'test/unit'
#require 'test/unit/ui/console/testrunner'
require 'assert-text-equal'
require 'yaml'
require 'testutil'
require 'erubis'


Test::Unit::TestCase.class_eval do
  if RUBY_VERSION >= "1.9"
    ## minitest doesn't have 'name()' method
    def name
      @name || @__name__
    end
    def ruby19
      yield
    end
  else
    def ruby19
    end
  end
end


if $0 == __FILE__
  require "#{TESTDIR}/test-erubis.rb"
  require "#{TESTDIR}/test-engines.rb"
  require "#{TESTDIR}/test-enhancers.rb"
  require "#{TESTDIR}/test-main.rb"
  require "#{TESTDIR}/test-users-guide.rb"
end
