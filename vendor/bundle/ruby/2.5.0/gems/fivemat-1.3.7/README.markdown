# Fivemat

Why settle for a test output *format* when you can have a test output
*fivemat*?

I'm tired of the two *de facto* standards for test output:

1. Bunch of dots — Wait till the end to see what failed, and
   guess the dot count to estimate progress.
2. Extreme verbosity — See failures as they happen if you pay very,
   very close attention.

In other words, you can choose between "too little" or "too much."

I've looked at third party alternatives, but none of them did much for
me.  What I want is the middle ground: dots grouped by file.  Thus,
I give you Fivemat:

    DoohickeyTest ....
    KajiggerTest .........................F...........
      1) Failure:
      test_isnt_actually_nil(KajiggerTest) [test/kajigger_test.rb:17]:
      Expected nil to not be nil.
    WhatchamacallitTest ................................................
    WidgetTest ...E......
      2) Error:
      ZeroDivisionError: divided by 0
          test/widget_test.rb:20:in `/'
          test/widget_test.rb:20:in `test_dividing_by_1'

MiniTest, RSpec, and Cucumber are supported. Here, have some sample
Cucumber output:

    features/sign_in.feature ......F--........
      no button with value or id or text 'Go' found (Capybara::ElementNotFound)
      ./features/step_definitions/web_steps.rb:53:in `/^I press "([^"]*)"$/'
      ./features/sign_in.feature:10:in `When I press "Log In"'
    features/sign_out.feature .......
    features/sign_up.feature ...............................................

Enable profiling by setting the `FIVEMAT_PROFILE` variable in the environment:

    > FIVEMAT_PROFILE=1 rspec --format Fivemat
    Doohickey .... (0.27s)
    Kajigger ..................................... (1.87s)

## Usage

Start by adding `gem 'fivemat'` to your `Gemfile`.

### MiniTest

On MiniTest 5, it's loaded automatically as a plugin, and there's nothing else
to do.  Otherwise, change `require 'minitest/autorun'` to
`require 'fivemat/minitest/autorun'`.  Or with Rails, add
`require 'fivemat/minitest'` to `test/test_helper.rb`.  If it doesn't work, you
may need a newer version of MiniTest. (Add `gem 'minitest'` to your Gemfile if
it's not there already.)

### RSpec

Add `--format Fivemat` to `.rspec`.

### Cucumber

Add `--format Fivemat` to `cucumber.yml`.

## Contributing

Don't forget to include test coverage for any changes you introduce.
(Ha! I kid! Everybody knows it's impossible to test a test library.)

## License

Copyright © Tim Pope. MIT License.
