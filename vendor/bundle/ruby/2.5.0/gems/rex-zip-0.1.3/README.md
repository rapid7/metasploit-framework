# Rex::Zip

Ruby Exploitation(Rex) Library for creating Zip based archives such as *.zip, *.war, and *.jar files. Ported from the original
Metasploit Framework code written by jduck.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'rex-zip'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install rex-zip

## Usage

Creating a .zip example:

```ruby
msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end
inc = File.dirname(msfbase) + '/../../..'
$:.unshift(inc)

require 'rex/zip'

# example usage
zip = Rex::Zip::Archive.new
zip.add_file("elite.txt", "A" * 1024)
zip.save_to("lolz.zip")
```


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/rapid7/rex-zip. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

