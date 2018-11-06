# Nexpose-Client
[![Gem Version](https://badge.fury.io/rb/nexpose.svg)](http://badge.fury.io/rb/nexpose) [![Build Status](https://travis-ci.org/rapid7/nexpose-client.svg?branch=master)](https://travis-ci.org/rapid7/nexpose-client) [![Test Coverage](https://codeclimate.com/github/rapid7/nexpose-client/badges/coverage.svg)](https://codeclimate.com/github/rapid7/nexpose-client) [![Inline docs](http://inch-ci.org/github/rapid7/nexpose-client.svg?branch=master)](http://inch-ci.org/github/rapid7/nexpose-client) [![Code Climate](https://codeclimate.com/github/rapid7/nexpose-client/badges/gpa.svg)](https://codeclimate.com/github/rapid7/nexpose-client)

This is the official gem package for the Ruby Nexpose API client library.

For assistance with using the gem or to discuss different approaches, please open an issue. To share or discuss scripts which use the gem head over to the [Nexpose Resources](https://github.com/rapid7/nexpose-resources) project.

Check out the [wiki](https://github.com/rapid7/nexpose-client/wiki) for walk-throughs and other documentation. Submit bugs and feature requests on the [issues](https://github.com/rapid7/nexpose-client/issues) page.

This gem is heavily used for internal, automated testing of the Nexpose product. It provides calls to the Nexpose XML APIs version 1.1 and 1.2, and JSON API 2.1. It also includes a number of helper methods which are not currently exposed through alternate means.

Since version 1.0 nexpose-client uses [Semantic Versioning](http://semver.org/). This allows for confident use of the [pessimistic operator](https://robots.thoughtbot.com/rubys-pessimistic-operator) in scripts or larger ruby projects.

Install the gem with Rubygems: `gem install nexpose`

## Release Notes

Release notes are available on the [Releases](https://github.com/rapid7/nexpose-client/releases) page.

The full Changelog is available as well, on the [Changelog](https://github.com/rapid7/nexpose-client/blob/master/CHANGELOG.md) page.

## Contributions

We welcome contributions to this package. Please see [CONTRIBUTING](.github/CONTRIBUTING.md) for details.

Our coding standards include:

* Favor returning classes over key-value maps. Classes tend to be easier for users to manipulate and use.
* Unless otherwise noted, code should adhere to the Ruby Style Guide: https://github.com/bbatsov/ruby-style-guide
* Use YARDoc comment style to improve the API documentation of the gem.

Full usage examples or task-oriented scripts should be submitted to the [Nexpose Resources](https://github.com/rapid7/nexpose-resources) project. Smaller examples can be added to the [wiki](https://github.com/rapid7/nexpose-client/wiki).

## License

The nexpose-client gem is provided under the 3-Clause BSD License. See [COPYING](COPYING) for details.
 
## Credits

Rapid7, Inc.
