# Rails::Deprecated::Sanitizer

In Rails 4.2 HTML sanitization has been rewritten using a more secure library.

This gem includes the old behavior shipping with Rails 4.2 and before. It is
strictly provided to ease migration. It will be supported until Rails 5.

To downgrade add `gem 'rails-deprecated_sanitizer'` to your Gemfile.

See the Rails 4.2 upgrade guide for more information.

You can read more about the new sanitization implementation here: [rails-html-sanitizer](https://github.com/rails/rails-html-sanitizer).

# Reporting XSS Security Issues

The code provided here deals with XSS attacks and is therefore a security concern.
So if you find a security issue please follow the [regular security reporting guidelines](http://rubyonrails.org/security/).
