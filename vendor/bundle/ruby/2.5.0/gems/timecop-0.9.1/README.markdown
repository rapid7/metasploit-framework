# timecop

[![Build Status](https://secure.travis-ci.org/travisjeffery/timecop.svg)](http://travis-ci.org/travisjeffery/timecop)

## DESCRIPTION

A gem providing "time travel" and "time freezing" capabilities, making it dead simple to test time-dependent code.  It provides a unified method to mock Time.now, Date.today, and DateTime.now in a single call.

## INSTALL

`gem install timecop`

## FEATURES

- Freeze time to a specific point.
- Travel back to a specific point in time, but allow time to continue moving forward from there.
- Scale time by a given scaling factor that will cause time to move at an accelerated pace.
- No dependencies, can be used with _any_ ruby project
- Timecop api allows arguments to be passed into #freeze and #travel as one of the following:
  - Time instance
  - DateTime instance
  - Date instance
  - individual arguments (year, month, day, hour, minute, second)
  - a single integer argument that is interpreted as an offset in seconds from Time.now
- Nested calls to Timecop#travel and Timecop#freeze are supported -- each block will maintain its interpretation of now.
- Works with regular Ruby projects, and Ruby on Rails projects

## USAGE

Run a time-sensitive test

```ruby
joe = User.find(1)
joe.purchase_home()
assert !joe.mortgage_due?
# move ahead a month and assert that the mortgage is due
Timecop.freeze(Date.today + 30) do
  assert joe.mortgage_due?
end
```

You can mock the time for a set of tests easily via setup/teardown methods

```ruby
describe "some set of tests to mock" do
  before do
    Timecop.freeze(Time.local(1990))
  end

  after do
    Timecop.return
  end

  it "should do blah blah blah" do
  end
end
```

Set the time for the test environment of a rails app -- this is particularly
helpful if your whole application is time-sensitive.  It allows you to build
your test data at a single point in time, and to move in/out of that time as
appropriate (within your tests)

in config/environments/test.rb

```ruby
config.after_initialize do
  # Set Time.now to September 1, 2008 10:05:00 AM (at this instant), but allow it to move forward
  t = Time.local(2008, 9, 1, 10, 5, 0)
  Timecop.travel(t)
end
```

### The difference between Timecop.freeze and Timecop.travel

freeze is used to statically mock the concept of now. As your program executes,
Time.now will not change unless you make subsequent calls into the Timecop API.
travel, on the other hand, computes an offset between what we currently think
Time.now is (recall that we support nested traveling) and the time passed in.
It uses this offset to simulate the passage of time.  To demonstrate, consider
the following code snippets:

```ruby
new_time = Time.local(2008, 9, 1, 12, 0, 0)
Timecop.freeze(new_time)
sleep(10)
new_time == Time.now # ==> true

Timecop.return # "turn off" Timecop
Timecop.travel(new_time)
sleep(10)
new_time == Time.now # ==> false
```

### Timecop.scale

Let's say you want to test a "live" integration wherein entire days could pass by
in minutes while you're able to simulate "real" activity. For example, one such use case
is being able to test reports and invoices that run in 30 day cycles in very little time, while also
being able to simulate activity via subsequent calls to your application.

```ruby
# seconds will now seem like hours
Timecop.scale(3600)
Time.now
# => 2012-09-20 21:23:25 -0500
# seconds later, hours have passed and it's gone from 9pm at night to 6am in the morning
Time.now
# => 2012-09-21 06:22:59 -0500
```

See [#42](https://github.com/travisjeffery/timecop/pull/42) for more information, thanks to Ken Mayer, David Holcomb, and Pivotal Labs.

### Timecop.safe_mode

Safe mode forces you to use Timecop with the block syntax since it always puts time back the way it was. If you are running in safe mode and use Timecop without the block syntax `Timecop::SafeModeException` will be raised to tell the user they are not being safe.

``` ruby
# turn on safe mode
Timecop.safe_mode = true

# check if you are in safe mode
Timecop.safe_mode?
# => true

# using method without block
Timecop.freeze
# => Timecop::SafeModeException: Safe mode is enabled, only calls passing a block are allowed.
```

### Rails v Ruby Date/Time libraries

Sometimes [Rails Date/Time methods don't play nicely with Ruby Date/Time methods.](https://rails.lighthouseapp.com/projects/8994/tickets/6410-dateyesterday-datetoday)

Be careful mixing Ruby `Date.today` with Rails `Date.tomorrow` / `Date.yesterday` as things might break.

## Contribute

timecop is maintained by [travisjeffery](http://github.com/travisjeffery), and
was created by [jtrupiano](https://github.com/jtrupiano).

Here's the most direct way to get your work merged into the project.

- Fork the project
- Clone down your fork
- Create a feature branch
- Hack away and add tests, not necessarily in that order
- Make sure everything still passes by running tests
- If necessary, rebase your commits into logical chunks without errors
- Push the branch up to your fork
- Send a pull request for your branch

