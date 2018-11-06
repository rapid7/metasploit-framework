rspec-rails supports integration with Capybara out of the box by adding
its Capybara::DSL (visit/page) and Capybara::RSpecMatchers to the
examples in the applicable directories, which differ slightly between
Capybara 1.x and Capybara >= 2.x.

## Capybara::DSL

Adds the `visit` and `page` methods, which work together to simulate a
GET request and provide access to the result (via `page`).

## Capybara::RSpecMatchers

Exposes matchers used to specify expected HTML content (e.g. `should_not have_selector` will work correctly).

## Capybara 1.x

Capybara::DSL is added to examples in:

* spec/requests    # included by Capybara
* spec/controllers

Capybara::RSpecMatchers is added to examples in:

* spec/requests    # included by Capybara
* spec/controllers
* spec/views
* spec/helpers
* spec/mailers

## Capybara 2.0

To use Capybara 2.0, you need rspec-rails-2.11.1 or greater.

Capybara::DSL is added to examples in:

* spec/features

Capybara::RSpecMatchers is added to examples in:

* spec/features
* spec/controllers
* spec/views
* spec/helpers
* spec/mailers

## Upgrading to Capybara-2.0

Many users have been confused by the co-existence of the the
Capybara::DSL (visit/page) alongside the rack-test DSL
(get|post|put|delete|head/response.body) in examples in spec/requests
and spec/controllers. As of rspec-rails-2.11.1 and capybara-2.0.0.beta2, these
are separated as follows:

* Capybara::DSL is included `spec/features`
* rack-test DSL is included in `spec/requests` and `spec/controllers`

Capybara::RSpecMatchers is added to examples in:

* spec/features
* spec/controllers
* spec/views
* spec/helpers
* spec/mailers

If you're upgrading to Capybara-2.0 and you used visit/page in
spec/requests you'll want to move those examples to spec/features and
they should just work.

If you want to leave those examples in spec/requests, you can include
Capybara::DSL in those examples yourself as follows, but this is
absolutely not recommended as you will be overriding the intended
behavior and accepting the risks associated with doing so:

    # not recommended!
    RSpec.configure do |c|
      c.include Capybara::DSL, :file_path => "spec/requests"
    end
