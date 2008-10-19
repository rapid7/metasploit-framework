#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..'))

require 'test/unit'
require 'msf/core/option_container'

module Msf

class OptionContainer::UnitTest < Test::Unit::TestCase

	# Tests the initialization of the OptionContainer object
	def test_initialize
		# Make sure initialization works
		options = nil

		assert_block("initialize failed") {
			options = OptionContainer.new(
				'rhost' => [ OptAddress, true, nil, 'host.com' ],
				'rport' => [ OptPort,    true, nil, 1234       ])

			if (options == nil)
				false
			end

			true
		}

		# Make sure there are 2 options
		assert_equal(2, options.length, "invalid number of options #{options.length}")

		# Make sure that the constructor raises an argument error when
		# an invalid option is supplied
		assert_raise(ArgumentError, "initialize invalid failed") {
			OptionContainer.new(
				'rhost' => 'invalid');
		}
	end

	# Tests getting the value of an option
	def test_get
		options = OptionContainer.new(
			'rport' => [ OptPort, true, nil, 1234 ])

		assert_equal(1234, options.get('rport').default, 
				"option default does not match")
		assert_equal(true, options.get('rport').required?, 
				"option required does not match")
		assert_equal('rport', options['rport'].name, 
				"option name does not match")
	end

	# Tests validation
	def test_validate
		# Test validating required options
		options = OptionContainer.new(
			'rhost' => [ OptAddress, true ],
			'rport' => [ OptPort,    true ],
			'Lib'   => [ OptString        ])

		ds = DataStore.new

		assert_raise(OptionValidateError, "required validation failed") {
			options.validate(ds)
		}

		ds['rhost'] = 'www.invalid.host.tldinvalid'
		ds['rport'] = 1234

		assert_raise(OptionValidateError, "host validation failed") {
			options.validate(ds)
		}

		# Make sure address validation does work
		ds['rhost'] = 'www.google.com'

		assert_equal(true, options.validate(ds), "overall validation failed")

		# Make sure port validation does work
		ds['rport'] = 23423423

		assert_raise(OptionValidateError, "port validation failed") {
			options.validate(ds)
		}
	end

	# Make sure advanced additions work
	def test_advanced
		options = OptionContainer.new

		options.add_advanced_options(
			'DONKEY' => [ OptString, false ])
			
		assert_equal(true, options.get('DONKEY').advanced?, 
				"advanced option failed")
	end

	def test_builtin
		options = OptionContainer.new

		options.add_options(
			[
				Opt::RHOST,
				Opt::RPORT(135),
				Opt::LHOST('127.0.0.1'),
				Opt::SSL
			])

		assert_equal(135, options.get('RPORT').default, "invalid RPORT default")
		assert_equal(true, options.get('RPORT').required?, "invalid RPORT require")
		assert_equal('127.0.0.1', options.get('LHOST').default, "invalid LHOST default")
		assert_equal('LHOST', options.get('LHOST').name, "invalid LHOST name")
		assert_equal(false, options.get('SSL').default, "invalid SSL default")
	end

	def test_enum
		options = OptionContainer.new(
			'testenum' => [ OptEnum, true, 'desc', nil, ['none','one','done']]
			)
		
		ds = DataStore.new

		assert_raise(OptionValidateError, "enum required") {
			options.validate(ds)
		}
		
		ds['testenum'] = 'done'
		assert_equal(true, options.validate(ds), "enum valid")

		ds['testenum'] = 'foo'
		assert_raise(OptionValidateError, "enum invalid") {
			options.validate(ds)
		}

		assert_equal('desc (accepted: none, one, done)', options['testenum'].desc, 'desc')
	end
end

end