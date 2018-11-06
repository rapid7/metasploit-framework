RSpec::Support.require_rspec_matchers "built_in/base_matcher"

module RSpec
  module Matchers
    # Container module for all built-in matchers. The matcher classes are here
    # (rather than directly under `RSpec::Matchers`) in order to prevent name
    # collisions, since `RSpec::Matchers` gets included into the user's namespace.
    #
    # Autoloading is used to delay when the matcher classes get loaded, allowing
    # rspec-matchers to boot faster, and avoiding loading matchers the user is
    # not using.
    module BuiltIn
      autoload :BeAKindOf,               'rspec/matchers/built_in/be_kind_of'
      autoload :BeAnInstanceOf,          'rspec/matchers/built_in/be_instance_of'
      autoload :BeBetween,               'rspec/matchers/built_in/be_between'
      autoload :Be,                      'rspec/matchers/built_in/be'
      autoload :BeComparedTo,            'rspec/matchers/built_in/be'
      autoload :BeFalsey,                'rspec/matchers/built_in/be'
      autoload :BeNil,                   'rspec/matchers/built_in/be'
      autoload :BePredicate,             'rspec/matchers/built_in/be'
      autoload :BeTruthy,                'rspec/matchers/built_in/be'
      autoload :BeWithin,                'rspec/matchers/built_in/be_within'
      autoload :Change,                  'rspec/matchers/built_in/change'
      autoload :Compound,                'rspec/matchers/built_in/compound'
      autoload :ContainExactly,          'rspec/matchers/built_in/contain_exactly'
      autoload :Cover,                   'rspec/matchers/built_in/cover'
      autoload :EndWith,                 'rspec/matchers/built_in/start_or_end_with'
      autoload :Eq,                      'rspec/matchers/built_in/eq'
      autoload :Eql,                     'rspec/matchers/built_in/eql'
      autoload :Equal,                   'rspec/matchers/built_in/equal'
      autoload :Exist,                   'rspec/matchers/built_in/exist'
      autoload :Has,                     'rspec/matchers/built_in/has'
      autoload :HaveAttributes,          'rspec/matchers/built_in/have_attributes'
      autoload :Include,                 'rspec/matchers/built_in/include'
      autoload :All,                     'rspec/matchers/built_in/all'
      autoload :Match,                   'rspec/matchers/built_in/match'
      autoload :NegativeOperatorMatcher, 'rspec/matchers/built_in/operators'
      autoload :OperatorMatcher,         'rspec/matchers/built_in/operators'
      autoload :Output,                  'rspec/matchers/built_in/output'
      autoload :PositiveOperatorMatcher, 'rspec/matchers/built_in/operators'
      autoload :RaiseError,              'rspec/matchers/built_in/raise_error'
      autoload :RespondTo,               'rspec/matchers/built_in/respond_to'
      autoload :Satisfy,                 'rspec/matchers/built_in/satisfy'
      autoload :StartWith,               'rspec/matchers/built_in/start_or_end_with'
      autoload :ThrowSymbol,             'rspec/matchers/built_in/throw_symbol'
      autoload :YieldControl,            'rspec/matchers/built_in/yield'
      autoload :YieldSuccessiveArgs,     'rspec/matchers/built_in/yield'
      autoload :YieldWithArgs,           'rspec/matchers/built_in/yield'
      autoload :YieldWithNoArgs,         'rspec/matchers/built_in/yield'
    end
  end
end
