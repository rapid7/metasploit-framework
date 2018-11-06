require 'rspec/support'
RSpec::Support.require_rspec_support 'matcher_definition'
RSpec::Support.define_optimized_require_for_rspec(:matchers) { |f| require_relative(f) }

%w[
  english_phrasing
  composable
  built_in
  generated_descriptions
  dsl
  matcher_delegator
  aliased_matcher
  expecteds_for_multiple_diffs
].each { |file| RSpec::Support.require_rspec_matchers(file) }

# RSpec's top level namespace. All of rspec-expectations is contained
# in the `RSpec::Expectations` and `RSpec::Matchers` namespaces.
module RSpec
  # RSpec::Matchers provides a number of useful matchers we use to define
  # expectations. Any object that implements the [matcher protocol](Matchers/MatcherProtocol)
  # can be used as a matcher.
  #
  # ## Predicates
  #
  # In addition to matchers that are defined explicitly, RSpec will create
  # custom matchers on the fly for any arbitrary predicate, giving your specs a
  # much more natural language feel.
  #
  # A Ruby predicate is a method that ends with a "?" and returns true or false.
  # Common examples are `empty?`, `nil?`, and `instance_of?`.
  #
  # All you need to do is write `expect(..).to be_` followed by the predicate
  # without the question mark, and RSpec will figure it out from there.
  # For example:
  #
  #     expect([]).to be_empty     # => [].empty?() | passes
  #     expect([]).not_to be_empty # => [].empty?() | fails
  #
  # In addtion to prefixing the predicate matchers with "be_", you can also use "be_a_"
  # and "be_an_", making your specs read much more naturally:
  #
  #     expect("a string").to be_an_instance_of(String) # =>"a string".instance_of?(String) # passes
  #
  #     expect(3).to be_a_kind_of(Integer)          # => 3.kind_of?(Numeric)     | passes
  #     expect(3).to be_a_kind_of(Numeric)          # => 3.kind_of?(Numeric)     | passes
  #     expect(3).to be_an_instance_of(Integer)     # => 3.instance_of?(Integer) | passes
  #     expect(3).not_to be_an_instance_of(Numeric) # => 3.instance_of?(Numeric) | fails
  #
  # RSpec will also create custom matchers for predicates like `has_key?`. To
  # use this feature, just state that the object should have_key(:key) and RSpec will
  # call has_key?(:key) on the target. For example:
  #
  #     expect(:a => "A").to have_key(:a)
  #     expect(:a => "A").to have_key(:b) # fails
  #
  # You can use this feature to invoke any predicate that begins with "has_", whether it is
  # part of the Ruby libraries (like `Hash#has_key?`) or a method you wrote on your own class.
  #
  # Note that RSpec does not provide composable aliases for these dynamic predicate
  # matchers. You can easily define your own aliases, though:
  #
  #     RSpec::Matchers.alias_matcher :a_user_who_is_an_admin, :be_an_admin
  #     expect(user_list).to include(a_user_who_is_an_admin)
  #
  # ## Alias Matchers
  #
  # With {RSpec::Matchers.alias_matcher}, you can easily create an
  # alternate name for a given matcher.
  #
  # The description will also change according to the new name:
  #
  #     RSpec::Matchers.alias_matcher :a_list_that_sums_to, :sum_to
  #     sum_to(3).description # => "sum to 3"
  #     a_list_that_sums_to(3).description # => "a list that sums to 3"
  #
  # or you can specify a custom description like this:
  #
  #     RSpec::Matchers.alias_matcher :a_list_sorted_by, :be_sorted_by do |description|
  #       description.sub("be sorted by", "a list sorted by")
  #     end
  #
  #     be_sorted_by(:age).description # => "be sorted by age"
  #     a_list_sorted_by(:age).description # => "a list sorted by age"
  #
  # ## Custom Matchers
  #
  # When you find that none of the stock matchers provide a natural feeling
  # expectation, you can very easily write your own using RSpec's matcher DSL
  # or writing one from scratch.
  #
  # ### Matcher DSL
  #
  # Imagine that you are writing a game in which players can be in various
  # zones on a virtual board. To specify that bob should be in zone 4, you
  # could say:
  #
  #     expect(bob.current_zone).to eql(Zone.new("4"))
  #
  # But you might find it more expressive to say:
  #
  #     expect(bob).to be_in_zone("4")
  #
  # and/or
  #
  #     expect(bob).not_to be_in_zone("3")
  #
  # You can create such a matcher like so:
  #
  #     RSpec::Matchers.define :be_in_zone do |zone|
  #       match do |player|
  #         player.in_zone?(zone)
  #       end
  #     end
  #
  # This will generate a <tt>be_in_zone</tt> method that returns a matcher
  # with logical default messages for failures. You can override the failure
  # messages and the generated description as follows:
  #
  #     RSpec::Matchers.define :be_in_zone do |zone|
  #       match do |player|
  #         player.in_zone?(zone)
  #       end
  #
  #       failure_message do |player|
  #         # generate and return the appropriate string.
  #       end
  #
  #       failure_message_when_negated do |player|
  #         # generate and return the appropriate string.
  #       end
  #
  #       description do
  #         # generate and return the appropriate string.
  #       end
  #     end
  #
  # Each of the message-generation methods has access to the block arguments
  # passed to the <tt>create</tt> method (in this case, <tt>zone</tt>). The
  # failure message methods (<tt>failure_message</tt> and
  # <tt>failure_message_when_negated</tt>) are passed the actual value (the
  # receiver of <tt>expect(..)</tt> or <tt>expect(..).not_to</tt>).
  #
  # ### Custom Matcher from scratch
  #
  # You could also write a custom matcher from scratch, as follows:
  #
  #     class BeInZone
  #       def initialize(expected)
  #         @expected = expected
  #       end
  #
  #       def matches?(target)
  #         @target = target
  #         @target.current_zone.eql?(Zone.new(@expected))
  #       end
  #
  #       def failure_message
  #         "expected #{@target.inspect} to be in Zone #{@expected}"
  #       end
  #
  #       def failure_message_when_negated
  #         "expected #{@target.inspect} not to be in Zone #{@expected}"
  #       end
  #     end
  #
  # ... and a method like this:
  #
  #     def be_in_zone(expected)
  #       BeInZone.new(expected)
  #     end
  #
  # And then expose the method to your specs. This is normally done
  # by including the method and the class in a module, which is then
  # included in your spec:
  #
  #     module CustomGameMatchers
  #       class BeInZone
  #         # ...
  #       end
  #
  #       def be_in_zone(expected)
  #         # ...
  #       end
  #     end
  #
  #     describe "Player behaviour" do
  #       include CustomGameMatchers
  #       # ...
  #     end
  #
  # or you can include in globally in a spec_helper.rb file <tt>require</tt>d
  # from your spec file(s):
  #
  #     RSpec::configure do |config|
  #       config.include(CustomGameMatchers)
  #     end
  #
  # ### Making custom matchers composable
  #
  # RSpec's built-in matchers are designed to be composed, in expressions like:
  #
  #     expect(["barn", 2.45]).to contain_exactly(
  #       a_value_within(0.1).of(2.5),
  #       a_string_starting_with("bar")
  #     )
  #
  # Custom matchers can easily participate in composed matcher expressions like these.
  # Include {RSpec::Matchers::Composable} in your custom matcher to make it support
  # being composed (matchers defined using the DSL have this included automatically).
  # Within your matcher's `matches?` method (or the `match` block, if using the DSL),
  # use `values_match?(expected, actual)` rather than `expected == actual`.
  # Under the covers, `values_match?` is able to match arbitrary
  # nested data structures containing a mix of both matchers and non-matcher objects.
  # It uses `===` and `==` to perform the matching, considering the values to
  # match if either returns `true`. The `Composable` mixin also provides some helper
  # methods for surfacing the matcher descriptions within your matcher's description
  # or failure messages.
  #
  # RSpec's built-in matchers each have a number of aliases that rephrase the matcher
  # from a verb phrase (such as `be_within`) to a noun phrase (such as `a_value_within`),
  # which reads better when the matcher is passed as an argument in a composed matcher
  # expressions, and also uses the noun-phrase wording in the matcher's `description`,
  # for readable failure messages. You can alias your custom matchers in similar fashion
  # using {RSpec::Matchers.alias_matcher}.
  #
  # ## Negated Matchers
  #
  # Sometimes if you want to test for the opposite using a more descriptive name
  # instead of using `not_to`, you can use {RSpec::Matchers.define_negated_matcher}:
  #
  #     RSpec::Matchers.define_negated_matcher :exclude, :include
  #     include(1, 2).description # => "include 1 and 2"
  #     exclude(1, 2).description # => "exclude 1 and 2"
  #
  # While the most obvious negated form may be to add a `not_` prefix,
  # the failure messages you get with that form can be confusing (e.g.
  # "expected [actual] to not [verb], but did not"). We've found it works
  # best to find a more positive name for the negated form, such as
  # `avoid_changing` rather than `not_change`.
  #
  module Matchers
    extend ::RSpec::Matchers::DSL

    # @!macro [attach] alias_matcher
    #   @!parse
    #     alias $1 $2
    # @!visibility private
    # We define this override here so we can attach a YARD macro to it.
    # It ensures that our docs list all the matcher aliases.
    def self.alias_matcher(*args, &block)
      super(*args, &block)
    end

    # @!method self.alias_matcher(new_name, old_name, options={}, &description_override)
    #   Extended from {RSpec::Matchers::DSL#alias_matcher}.

    # @!method self.define(name, &declarations)
    #   Extended from {RSpec::Matchers::DSL#define}.

    # @!method self.define_negated_matcher(negated_name, base_name, &description_override)
    #   Extended from {RSpec::Matchers::DSL#define_negated_matcher}.

    # @method expect
    # Supports `expect(actual).to matcher` syntax by wrapping `actual` in an
    # `ExpectationTarget`.
    # @example
    #   expect(actual).to eq(expected)
    #   expect(actual).not_to eq(expected)
    # @return [ExpectationTarget]
    # @see ExpectationTarget#to
    # @see ExpectationTarget#not_to

    # Allows multiple expectations in the provided block to fail, and then
    # aggregates them into a single exception, rather than aborting on the
    # first expectation failure like normal. This allows you to see all
    # failures from an entire set of expectations without splitting each
    # off into its own example (which may slow things down if the example
    # setup is expensive).
    #
    # @param label [String] label for this aggregation block, which will be
    #   included in the aggregated exception message.
    # @param metadata [Hash] additional metadata about this failure aggregation
    #   block. If multiple expectations fail, it will be exposed from the
    #   {Expectations::MultipleExpectationsNotMetError} exception. Mostly
    #   intended for internal RSpec use but you can use it as well.
    # @yield Block containing as many expectation as you want. The block is
    #   simply yielded to, so you can trust that anything that works outside
    #   the block should work within it.
    # @raise [Expectations::MultipleExpectationsNotMetError] raised when
    #   multiple expectations fail.
    # @raise [Expectations::ExpectationNotMetError] raised when a single
    #   expectation fails.
    # @raise [Exception] other sorts of exceptions will be raised as normal.
    #
    # @example
    #   aggregate_failures("verifying response") do
    #     expect(response.status).to eq(200)
    #     expect(response.headers).to include("Content-Type" => "text/plain")
    #     expect(response.body).to include("Success")
    #   end
    #
    # @note The implementation of this feature uses a thread-local variable,
    #   which means that if you have an expectation failure in another thread,
    #   it'll abort like normal.
    def aggregate_failures(label=nil, metadata={}, &block)
      Expectations::FailureAggregator.new(label, metadata).aggregate(&block)
    end

    # Passes if actual is truthy (anything but false or nil)
    def be_truthy
      BuiltIn::BeTruthy.new
    end
    alias_matcher :a_truthy_value, :be_truthy

    # Passes if actual is falsey (false or nil)
    def be_falsey
      BuiltIn::BeFalsey.new
    end
    alias_matcher :be_falsy,       :be_falsey
    alias_matcher :a_falsey_value, :be_falsey
    alias_matcher :a_falsy_value,  :be_falsey

    # Passes if actual is nil
    def be_nil
      BuiltIn::BeNil.new
    end
    alias_matcher :a_nil_value, :be_nil

    # @example
    #   expect(actual).to     be_truthy
    #   expect(actual).to     be_falsey
    #   expect(actual).to     be_nil
    #   expect(actual).to     be_[arbitrary_predicate](*args)
    #   expect(actual).not_to be_nil
    #   expect(actual).not_to be_[arbitrary_predicate](*args)
    #
    # Given true, false, or nil, will pass if actual value is true, false or
    # nil (respectively). Given no args means the caller should satisfy an if
    # condition (to be or not to be).
    #
    # Predicates are any Ruby method that ends in a "?" and returns true or
    # false.  Given be_ followed by arbitrary_predicate (without the "?"),
    # RSpec will match convert that into a query against the target object.
    #
    # The arbitrary_predicate feature will handle any predicate prefixed with
    # "be_an_" (e.g. be_an_instance_of), "be_a_" (e.g. be_a_kind_of) or "be_"
    # (e.g. be_empty), letting you choose the prefix that best suits the
    # predicate.
    def be(*args)
      args.empty? ? Matchers::BuiltIn::Be.new : equal(*args)
    end
    alias_matcher :a_value, :be, :klass => AliasedMatcherWithOperatorSupport

    # passes if target.kind_of?(klass)
    def be_a(klass)
      be_a_kind_of(klass)
    end
    alias_method :be_an, :be_a

    # Passes if actual.instance_of?(expected)
    #
    # @example
    #   expect(5).to     be_an_instance_of(Integer)
    #   expect(5).not_to be_an_instance_of(Numeric)
    #   expect(5).not_to be_an_instance_of(Float)
    def be_an_instance_of(expected)
      BuiltIn::BeAnInstanceOf.new(expected)
    end
    alias_method :be_instance_of, :be_an_instance_of
    alias_matcher :an_instance_of, :be_an_instance_of

    # Passes if actual.kind_of?(expected)
    #
    # @example
    #   expect(5).to     be_a_kind_of(Integer)
    #   expect(5).to     be_a_kind_of(Numeric)
    #   expect(5).not_to be_a_kind_of(Float)
    def be_a_kind_of(expected)
      BuiltIn::BeAKindOf.new(expected)
    end
    alias_method :be_kind_of, :be_a_kind_of
    alias_matcher :a_kind_of,  :be_a_kind_of

    # Passes if actual.between?(min, max). Works with any Comparable object,
    # including String, Symbol, Time, or Numeric (Fixnum, Bignum, Integer,
    # Float, Complex, and Rational).
    #
    # By default, `be_between` is inclusive (i.e. passes when given either the max or min value),
    # but you can make it `exclusive` by chaining that off the matcher.
    #
    # @example
    #   expect(5).to      be_between(1, 10)
    #   expect(11).not_to be_between(1, 10)
    #   expect(10).not_to be_between(1, 10).exclusive
    def be_between(min, max)
      BuiltIn::BeBetween.new(min, max)
    end
    alias_matcher :a_value_between, :be_between

    # Passes if actual == expected +/- delta
    #
    # @example
    #   expect(result).to     be_within(0.5).of(3.0)
    #   expect(result).not_to be_within(0.5).of(3.0)
    def be_within(delta)
      BuiltIn::BeWithin.new(delta)
    end
    alias_matcher :a_value_within, :be_within
    alias_matcher :within,         :be_within

    # Applied to a proc, specifies that its execution will cause some value to
    # change.
    #
    # @param [Object] receiver
    # @param [Symbol] message the message to send the receiver
    #
    # You can either pass <tt>receiver</tt> and <tt>message</tt>, or a block,
    # but not both.
    #
    # When passing a block, it must use the `{ ... }` format, not
    # do/end, as `{ ... }` binds to the `change` method, whereas do/end
    # would errantly bind to the `expect(..).to` or `expect(...).not_to` method.
    #
    # You can chain any of the following off of the end to specify details
    # about the change:
    #
    # * `from`
    # * `to`
    #
    # or any one of:
    #
    # * `by`
    # * `by_at_least`
    # * `by_at_most`
    #
    # @example
    #   expect {
    #     team.add_player(player)
    #   }.to change(roster, :count)
    #
    #   expect {
    #     team.add_player(player)
    #   }.to change(roster, :count).by(1)
    #
    #   expect {
    #     team.add_player(player)
    #   }.to change(roster, :count).by_at_least(1)
    #
    #   expect {
    #     team.add_player(player)
    #   }.to change(roster, :count).by_at_most(1)
    #
    #   string = "string"
    #   expect {
    #     string.reverse!
    #   }.to change { string }.from("string").to("gnirts")
    #
    #   string = "string"
    #   expect {
    #     string
    #   }.not_to change { string }.from("string")
    #
    #   expect {
    #     person.happy_birthday
    #   }.to change(person, :birthday).from(32).to(33)
    #
    #   expect {
    #     employee.develop_great_new_social_networking_app
    #   }.to change(employee, :title).from("Mail Clerk").to("CEO")
    #
    #   expect {
    #     doctor.leave_office
    #   }.to change(doctor, :sign).from(/is in/).to(/is out/)
    #
    #   user = User.new(:type => "admin")
    #   expect {
    #     user.symbolize_type
    #   }.to change(user, :type).from(String).to(Symbol)
    #
    # == Notes
    #
    # Evaluates `receiver.message` or `block` before and after it
    # evaluates the block passed to `expect`. If the value is the same
    # object, its before/after `hash` value is used to see if it has changed.
    # Therefore, your object needs to properly implement `hash` to work correctly
    # with this matcher.
    #
    # `expect( ... ).not_to change` supports the form that specifies `from`
    # (which specifies what you expect the starting, unchanged value to be)
    # but does not support forms with subsequent calls to `by`, `by_at_least`,
    # `by_at_most` or `to`.
    def change(receiver=nil, message=nil, &block)
      BuiltIn::Change.new(receiver, message, &block)
    end
    alias_matcher :a_block_changing,  :change
    alias_matcher :changing,          :change

    # Passes if actual contains all of the expected regardless of order.
    # This works for collections. Pass in multiple args and it will only
    # pass if all args are found in collection.
    #
    # @note This is also available using the `=~` operator with `should`,
    #       but `=~` is not supported with `expect`.
    #
    # @example
    #   expect([1, 2, 3]).to contain_exactly(1, 2, 3)
    #   expect([1, 2, 3]).to contain_exactly(1, 3, 2)
    #
    # @see #match_array
    def contain_exactly(*items)
      BuiltIn::ContainExactly.new(items)
    end
    alias_matcher :a_collection_containing_exactly, :contain_exactly
    alias_matcher :containing_exactly,              :contain_exactly

    # Passes if actual covers expected. This works for
    # Ranges. You can also pass in multiple args
    # and it will only pass if all args are found in Range.
    #
    # @example
    #   expect(1..10).to     cover(5)
    #   expect(1..10).to     cover(4, 6)
    #   expect(1..10).to     cover(4, 6, 11) # fails
    #   expect(1..10).not_to cover(11)
    #   expect(1..10).not_to cover(5)        # fails
    #
    # ### Warning:: Ruby >= 1.9 only
    def cover(*values)
      BuiltIn::Cover.new(*values)
    end
    alias_matcher :a_range_covering, :cover
    alias_matcher :covering,         :cover

    # Matches if the actual value ends with the expected value(s). In the case
    # of a string, matches against the last `expected.length` characters of the
    # actual string. In the case of an array, matches against the last
    # `expected.length` elements of the actual array.
    #
    # @example
    #   expect("this string").to   end_with "string"
    #   expect([0, 1, 2, 3, 4]).to end_with 4
    #   expect([0, 2, 3, 4, 4]).to end_with 3, 4
    def end_with(*expected)
      BuiltIn::EndWith.new(*expected)
    end
    alias_matcher :a_collection_ending_with, :end_with
    alias_matcher :a_string_ending_with,     :end_with
    alias_matcher :ending_with,              :end_with

    # Passes if <tt>actual == expected</tt>.
    #
    # See http://www.ruby-doc.org/core/classes/Object.html#M001057 for more
    # information about equality in Ruby.
    #
    # @example
    #   expect(5).to     eq(5)
    #   expect(5).not_to eq(3)
    def eq(expected)
      BuiltIn::Eq.new(expected)
    end
    alias_matcher :an_object_eq_to, :eq
    alias_matcher :eq_to,           :eq

    # Passes if `actual.eql?(expected)`
    #
    # See http://www.ruby-doc.org/core/classes/Object.html#M001057 for more
    # information about equality in Ruby.
    #
    # @example
    #   expect(5).to     eql(5)
    #   expect(5).not_to eql(3)
    def eql(expected)
      BuiltIn::Eql.new(expected)
    end
    alias_matcher :an_object_eql_to, :eql
    alias_matcher :eql_to,           :eql

    # Passes if <tt>actual.equal?(expected)</tt> (object identity).
    #
    # See http://www.ruby-doc.org/core/classes/Object.html#M001057 for more
    # information about equality in Ruby.
    #
    # @example
    #   expect(5).to       equal(5)   # Integers are equal
    #   expect("5").not_to equal("5") # Strings that look the same are not the same object
    def equal(expected)
      BuiltIn::Equal.new(expected)
    end
    alias_matcher :an_object_equal_to, :equal
    alias_matcher :equal_to,           :equal

    # Passes if `actual.exist?` or `actual.exists?`
    #
    # @example
    #   expect(File).to exist("path/to/file")
    def exist(*args)
      BuiltIn::Exist.new(*args)
    end
    alias_matcher :an_object_existing, :exist
    alias_matcher :existing,           :exist

    # Passes if actual's attribute values match the expected attributes hash.
    # This works no matter how you define your attribute readers.
    #
    # @example
    #   Person = Struct.new(:name, :age)
    #   person = Person.new("Bob", 32)
    #
    #   expect(person).to have_attributes(:name => "Bob", :age => 32)
    #   expect(person).to have_attributes(:name => a_string_starting_with("B"), :age => (a_value > 30) )
    #
    # @note It will fail if actual doesn't respond to any of the expected attributes.
    #
    # @example
    #   expect(person).to have_attributes(:color => "red")
    def have_attributes(expected)
      BuiltIn::HaveAttributes.new(expected)
    end
    alias_matcher :an_object_having_attributes, :have_attributes
    alias_matcher :having_attributes,           :have_attributes

    # Passes if actual includes expected. This works for
    # collections and Strings. You can also pass in multiple args
    # and it will only pass if all args are found in collection.
    #
    # @example
    #   expect([1,2,3]).to      include(3)
    #   expect([1,2,3]).to      include(2,3)
    #   expect([1,2,3]).to      include(2,3,4) # fails
    #   expect([1,2,3]).not_to  include(4)
    #   expect("spread").to     include("read")
    #   expect("spread").not_to include("red")
    #   expect(:a => 1, :b => 2).to include(:a)
    #   expect(:a => 1, :b => 2).to include(:a, :b)
    #   expect(:a => 1, :b => 2).to include(:a => 1)
    #   expect(:a => 1, :b => 2).to include(:b => 2, :a => 1)
    #   expect(:a => 1, :b => 2).to include(:c) # fails
    #   expect(:a => 1, :b => 2).not_to include(:a => 2)
    def include(*expected)
      BuiltIn::Include.new(*expected)
    end
    alias_matcher :a_collection_including, :include
    alias_matcher :a_string_including,     :include
    alias_matcher :a_hash_including,       :include
    alias_matcher :including,              :include

    # Passes if the provided matcher passes when checked against all
    # elements of the collection.
    #
    # @example
    #   expect([1, 3, 5]).to all be_odd
    #   expect([1, 3, 6]).to all be_odd # fails
    #
    # @note The negative form `not_to all` is not supported. Instead
    #   use `not_to include` or pass a negative form of a matcher
    #   as the argument (e.g. `all exclude(:foo)`).
    #
    # @note You can also use this with compound matchers as well.
    #
    # @example
    #   expect([1, 3, 5]).to all( be_odd.and be_an(Integer) )
    def all(expected)
      BuiltIn::All.new(expected)
    end

    # Given a `Regexp` or `String`, passes if `actual.match(pattern)`
    # Given an arbitrary nested data structure (e.g. arrays and hashes),
    # matches if `expected === actual` || `actual == expected` for each
    # pair of elements.
    #
    # @example
    #   expect(email).to match(/^([^\s]+)((?:[-a-z0-9]+\.)+[a-z]{2,})$/i)
    #   expect(email).to match("@example.com")
    #
    # @example
    #   hash = {
    #     :a => {
    #       :b => ["foo", 5],
    #       :c => { :d => 2.05 }
    #     }
    #   }
    #
    #   expect(hash).to match(
    #     :a => {
    #       :b => a_collection_containing_exactly(
    #         a_string_starting_with("f"),
    #         an_instance_of(Integer)
    #       ),
    #       :c => { :d => (a_value < 3) }
    #     }
    #   )
    #
    # @note The `match_regex` alias is deprecated and is not recommended for use.
    #       It was added in 2.12.1 to facilitate its use from within custom
    #       matchers (due to how the custom matcher DSL was evaluated in 2.x,
    #       `match` could not be used there), but is no longer needed in 3.x.
    def match(expected)
      BuiltIn::Match.new(expected)
    end
    alias_matcher :match_regex,        :match
    alias_matcher :an_object_matching, :match
    alias_matcher :a_string_matching,  :match
    alias_matcher :matching,           :match

    # An alternate form of `contain_exactly` that accepts
    # the expected contents as a single array arg rather
    # that splatted out as individual items.
    #
    # @example
    #   expect(results).to contain_exactly(1, 2)
    #   # is identical to:
    #   expect(results).to match_array([1, 2])
    #
    # @see #contain_exactly
    def match_array(items)
      contain_exactly(*items)
    end

    # With no arg, passes if the block outputs `to_stdout` or `to_stderr`.
    # With a string, passes if the block outputs that specific string `to_stdout` or `to_stderr`.
    # With a regexp or matcher, passes if the block outputs a string `to_stdout` or `to_stderr` that matches.
    #
    # To capture output from any spawned subprocess as well, use `to_stdout_from_any_process` or
    # `to_stderr_from_any_process`. Output from any process that inherits the main process's corresponding
    # standard stream will be captured.
    #
    # @example
    #   expect { print 'foo' }.to output.to_stdout
    #   expect { print 'foo' }.to output('foo').to_stdout
    #   expect { print 'foo' }.to output(/foo/).to_stdout
    #
    #   expect { do_something }.to_not output.to_stdout
    #
    #   expect { warn('foo') }.to output.to_stderr
    #   expect { warn('foo') }.to output('foo').to_stderr
    #   expect { warn('foo') }.to output(/foo/).to_stderr
    #
    #   expect { do_something }.to_not output.to_stderr
    #
    #   expect { system('echo foo') }.to output("foo\n").to_stdout_from_any_process
    #   expect { system('echo foo', out: :err) }.to output("foo\n").to_stderr_from_any_process
    #
    # @note `to_stdout` and `to_stderr` work by temporarily replacing `$stdout` or `$stderr`,
    #   so they're not able to intercept stream output that explicitly uses `STDOUT`/`STDERR`
    #   or that uses a reference to `$stdout`/`$stderr` that was stored before the
    #   matcher was used.
    # @note `to_stdout_from_any_process` and `to_stderr_from_any_process` use Tempfiles, and
    #   are thus significantly (~30x) slower than `to_stdout` and `to_stderr`.
    def output(expected=nil)
      BuiltIn::Output.new(expected)
    end
    alias_matcher :a_block_outputting, :output

    # With no args, matches if any error is raised.
    # With a named error, matches only if that specific error is raised.
    # With a named error and messsage specified as a String, matches only if both match.
    # With a named error and messsage specified as a Regexp, matches only if both match.
    # Pass an optional block to perform extra verifications on the exception matched
    #
    # @example
    #   expect { do_something_risky }.to raise_error
    #   expect { do_something_risky }.to raise_error(PoorRiskDecisionError)
    #   expect { do_something_risky }.to raise_error(PoorRiskDecisionError) { |error| expect(error.data).to eq 42 }
    #   expect { do_something_risky }.to raise_error(PoorRiskDecisionError, "that was too risky")
    #   expect { do_something_risky }.to raise_error(PoorRiskDecisionError, /oo ri/)
    #
    #   expect { do_something_risky }.not_to raise_error
    def raise_error(error=nil, message=nil, &block)
      BuiltIn::RaiseError.new(error, message, &block)
    end
    alias_method :raise_exception,  :raise_error

    alias_matcher :a_block_raising,  :raise_error do |desc|
      desc.sub("raise", "a block raising")
    end

    alias_matcher :raising,        :raise_error do |desc|
      desc.sub("raise", "raising")
    end

    # Matches if the target object responds to all of the names
    # provided. Names can be Strings or Symbols.
    #
    # @example
    #   expect("string").to respond_to(:length)
    #
    def respond_to(*names)
      BuiltIn::RespondTo.new(*names)
    end
    alias_matcher :an_object_responding_to, :respond_to
    alias_matcher :responding_to,           :respond_to

    # Passes if the submitted block returns true. Yields target to the
    # block.
    #
    # Generally speaking, this should be thought of as a last resort when
    # you can't find any other way to specify the behaviour you wish to
    # specify.
    #
    # If you do find yourself in such a situation, you could always write
    # a custom matcher, which would likely make your specs more expressive.
    #
    # @param description [String] optional description to be used for this matcher.
    #
    # @example
    #   expect(5).to satisfy { |n| n > 3 }
    #   expect(5).to satisfy("be greater than 3") { |n| n > 3 }
    def satisfy(description=nil, &block)
      BuiltIn::Satisfy.new(description, &block)
    end
    alias_matcher :an_object_satisfying, :satisfy
    alias_matcher :satisfying,           :satisfy

    # Matches if the actual value starts with the expected value(s). In the
    # case of a string, matches against the first `expected.length` characters
    # of the actual string. In the case of an array, matches against the first
    # `expected.length` elements of the actual array.
    #
    # @example
    #   expect("this string").to   start_with "this s"
    #   expect([0, 1, 2, 3, 4]).to start_with 0
    #   expect([0, 2, 3, 4, 4]).to start_with 0, 1
    def start_with(*expected)
      BuiltIn::StartWith.new(*expected)
    end
    alias_matcher :a_collection_starting_with, :start_with
    alias_matcher :a_string_starting_with,     :start_with
    alias_matcher :starting_with,              :start_with

    # Given no argument, matches if a proc throws any Symbol.
    #
    # Given a Symbol, matches if the given proc throws the specified Symbol.
    #
    # Given a Symbol and an arg, matches if the given proc throws the
    # specified Symbol with the specified arg.
    #
    # @example
    #   expect { do_something_risky }.to throw_symbol
    #   expect { do_something_risky }.to throw_symbol(:that_was_risky)
    #   expect { do_something_risky }.to throw_symbol(:that_was_risky, 'culprit')
    #
    #   expect { do_something_risky }.not_to throw_symbol
    #   expect { do_something_risky }.not_to throw_symbol(:that_was_risky)
    #   expect { do_something_risky }.not_to throw_symbol(:that_was_risky, 'culprit')
    def throw_symbol(expected_symbol=nil, expected_arg=nil)
      BuiltIn::ThrowSymbol.new(expected_symbol, expected_arg)
    end

    alias_matcher :a_block_throwing, :throw_symbol do |desc|
      desc.sub("throw", "a block throwing")
    end

    alias_matcher :throwing,        :throw_symbol do |desc|
      desc.sub("throw", "throwing")
    end

    # Passes if the method called in the expect block yields, regardless
    # of whether or not arguments are yielded.
    #
    # @example
    #   expect { |b| 5.tap(&b) }.to yield_control
    #   expect { |b| "a".to_sym(&b) }.not_to yield_control
    #
    # @note Your expect block must accept a parameter and pass it on to
    #   the method-under-test as a block.
    def yield_control
      BuiltIn::YieldControl.new
    end
    alias_matcher :a_block_yielding_control,  :yield_control
    alias_matcher :yielding_control,          :yield_control

    # Passes if the method called in the expect block yields with
    # no arguments. Fails if it does not yield, or yields with arguments.
    #
    # @example
    #   expect { |b| User.transaction(&b) }.to yield_with_no_args
    #   expect { |b| 5.tap(&b) }.not_to yield_with_no_args # because it yields with `5`
    #   expect { |b| "a".to_sym(&b) }.not_to yield_with_no_args # because it does not yield
    #
    # @note Your expect block must accept a parameter and pass it on to
    #   the method-under-test as a block.
    # @note This matcher is not designed for use with methods that yield
    #   multiple times.
    def yield_with_no_args
      BuiltIn::YieldWithNoArgs.new
    end
    alias_matcher :a_block_yielding_with_no_args,  :yield_with_no_args
    alias_matcher :yielding_with_no_args,          :yield_with_no_args

    # Given no arguments, matches if the method called in the expect
    # block yields with arguments (regardless of what they are or how
    # many there are).
    #
    # Given arguments, matches if the method called in the expect block
    # yields with arguments that match the given arguments.
    #
    # Argument matching is done using `===` (the case match operator)
    # and `==`. If the expected and actual arguments match with either
    # operator, the matcher will pass.
    #
    # @example
    #   expect { |b| 5.tap(&b) }.to yield_with_args # because #tap yields an arg
    #   expect { |b| 5.tap(&b) }.to yield_with_args(5) # because 5 == 5
    #   expect { |b| 5.tap(&b) }.to yield_with_args(Integer) # because Integer === 5
    #   expect { |b| File.open("f.txt", &b) }.to yield_with_args(/txt/) # because /txt/ === "f.txt"
    #
    #   expect { |b| User.transaction(&b) }.not_to yield_with_args # because it yields no args
    #   expect { |b| 5.tap(&b) }.not_to yield_with_args(1, 2, 3)
    #
    # @note Your expect block must accept a parameter and pass it on to
    #   the method-under-test as a block.
    # @note This matcher is not designed for use with methods that yield
    #   multiple times.
    def yield_with_args(*args)
      BuiltIn::YieldWithArgs.new(*args)
    end
    alias_matcher :a_block_yielding_with_args,  :yield_with_args
    alias_matcher :yielding_with_args,          :yield_with_args

    # Designed for use with methods that repeatedly yield (such as
    # iterators). Passes if the method called in the expect block yields
    # multiple times with arguments matching those given.
    #
    # Argument matching is done using `===` (the case match operator)
    # and `==`. If the expected and actual arguments match with either
    # operator, the matcher will pass.
    #
    # @example
    #   expect { |b| [1, 2, 3].each(&b) }.to yield_successive_args(1, 2, 3)
    #   expect { |b| { :a => 1, :b => 2 }.each(&b) }.to yield_successive_args([:a, 1], [:b, 2])
    #   expect { |b| [1, 2, 3].each(&b) }.not_to yield_successive_args(1, 2)
    #
    # @note Your expect block must accept a parameter and pass it on to
    #   the method-under-test as a block.
    def yield_successive_args(*args)
      BuiltIn::YieldSuccessiveArgs.new(*args)
    end
    alias_matcher :a_block_yielding_successive_args,  :yield_successive_args
    alias_matcher :yielding_successive_args,          :yield_successive_args

    # Delegates to {RSpec::Expectations.configuration}.
    # This is here because rspec-core's `expect_with` option
    # looks for a `configuration` method on the mixin
    # (`RSpec::Matchers`) to yield to a block.
    # @return [RSpec::Expectations::Configuration] the configuration object
    def self.configuration
      Expectations.configuration
    end

  private

    BE_PREDICATE_REGEX = /^(be_(?:an?_)?)(.*)/
    HAS_REGEX = /^(?:have_)(.*)/
    DYNAMIC_MATCHER_REGEX = Regexp.union(BE_PREDICATE_REGEX, HAS_REGEX)

    def method_missing(method, *args, &block)
      case method.to_s
      when BE_PREDICATE_REGEX
        BuiltIn::BePredicate.new(method, *args, &block)
      when HAS_REGEX
        BuiltIn::Has.new(method, *args, &block)
      else
        super
      end
    end

    if RUBY_VERSION.to_f >= 1.9
      def respond_to_missing?(method, *)
        method =~ DYNAMIC_MATCHER_REGEX || super
      end
    else # for 1.8.7
      # :nocov:
      def respond_to?(method, *)
        method = method.to_s
        method =~ DYNAMIC_MATCHER_REGEX || super
      end
      public :respond_to?
      # :nocov:
    end

    # @api private
    def self.is_a_matcher?(obj)
      return true  if ::RSpec::Matchers::BuiltIn::BaseMatcher === obj
      begin
        return false if obj.respond_to?(:i_respond_to_everything_so_im_not_really_a_matcher)
      rescue NoMethodError
        # Some objects, like BasicObject, don't implemented standard
        # reflection methods.
        return false
      end
      return false unless obj.respond_to?(:matches?)

      obj.respond_to?(:failure_message) ||
      obj.respond_to?(:failure_message_for_should) # support legacy matchers
    end

    ::RSpec::Support.register_matcher_definition do |obj|
      is_a_matcher?(obj)
    end

    # @api private
    def self.is_a_describable_matcher?(obj)
      is_a_matcher?(obj) && obj.respond_to?(:description)
    end

    if RSpec::Support::Ruby.mri? && RUBY_VERSION[0, 3] == '1.9'
      # @api private
      # Note that `included` doesn't work for this because it is triggered
      # _after_ `RSpec::Matchers` is an ancestor of the inclusion host, rather
      # than _before_, like `append_features`. It's important we check this before
      # in order to find the cases where it was already previously included.
      def self.append_features(mod)
        return super if mod < self # `mod < self` indicates a re-inclusion.

        subclasses = ObjectSpace.each_object(Class).select { |c| c < mod && c < self }
        return super unless subclasses.any?

        subclasses.reject! { |s| subclasses.any? { |s2| s < s2 } } # Filter to the root ancestor.
        subclasses = subclasses.map { |s| "`#{s}`" }.join(", ")

        RSpec.warning "`#{self}` has been included in a superclass (`#{mod}`) " \
                      "after previously being included in subclasses (#{subclasses}), " \
                      "which can trigger infinite recursion from `super` due to an MRI 1.9 bug " \
                      "(https://redmine.ruby-lang.org/issues/3351). To work around this, " \
                      "either upgrade to MRI 2.0+, include a dup of the module (e.g. " \
                      "`include #{self}.dup`), or find a way to include `#{self}` in `#{mod}` " \
                      "before it is included in subclasses (#{subclasses}). See " \
                      "https://github.com/rspec/rspec-expectations/issues/814 for more info"

        super
      end
    end
  end
end
