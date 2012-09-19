# jquery-rails

jQuery! For Rails! So great.

This gem provides:

* jQuery 1.7.2
* jQuery UI 1.8.18
* the latest jQuery UJS adapter
* and Sam Ruby's assert_select_jquery function, which is automatically included for use in tests.

## Rails 3.1

For Rails 3.1 and greater, the files will be added to the asset pipeline and available for you to use. These two lines will be added to the file `app/assets/javascripts/application.js` by default:

    //= require jquery
    //= require jquery_ujs

If you wish to use jQuery UI as well, you can add this line to `application.js`:

    //= require jquery-ui

In order to use the themed parts of jQuery UI, you will also need to supply your own theme CSS. See [jqueryui.com](http://jqueryui.com) for more information.

### Installation

New Rails 3.1 apps include jquery-rails in the Gemfile by default. So just make a new app:

    rails new myapp

You're done!

## Rails 3.0

This gem adds a single generator to Rails 3, jquery:install. Running the generator will remove any Prototype JS files you may happen to have, fetch jQuery and the jQuery-ujs driver for Rails, and (optionally) fetch jQuery UI.

The gem will also hook into the Rails configuration process, removing Prototype and adding jQuery to the javascript files included by the `javascript_include_tag(:defaults)` call. While the plugin downloads minified and un-minified versions of jQuery and jQuery UI, only the minified versions are included in :default.

### Installation

In your Gemfile, add this line:

    gem "jquery-rails"

Then, run `bundle install`. To invoke the generator, run:

    rails generate jquery:install #--ui to enable jQuery UI

You're done!
