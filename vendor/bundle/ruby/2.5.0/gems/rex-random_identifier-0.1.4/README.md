# Rex::RandomIdentifier

Ruby Exploitation(Rex) Library for generating strings that conform to most standards for an identifier, i.e., begin with a letter and contain only alphanumeric characters and underscore.


## Installation

Add this line to your application's Gemfile:

```ruby
gem 'rex-random_identifier'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install rex-random_identifier

## Usage

Example
```ruby
   vars = Rex::RandomIdentifierGenerator.new
   asp_code = <<-END_CODE
     Sub #{vars[:func]}()
       Dim #{vars[:fso]}
       Set #{vars[:fso]} = CreateObject("Scripting.FileSystemObject")
       ...
     End Sub
     #{vars[:func]}
   END_CODE
#
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/rapid7/rex-random_identifier. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

