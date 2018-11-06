[![Gem Version](https://badge.fury.io/rb/openssl-ccm.png)](http://badge.fury.io/rb/openssl-ccm)
[![Dependency Status](https://gemnasium.com/SmallLars/openssl-ccm.png)](https://gemnasium.com/SmallLars/openssl-ccm)
[![Build Status](https://travis-ci.org/SmallLars/openssl-ccm.png?branch=master)](https://travis-ci.org/SmallLars/openssl-ccm)
[![Coverage Status](https://coveralls.io/repos/SmallLars/openssl-ccm/badge.png?branch=master)](https://coveralls.io/r/SmallLars/openssl-ccm)
[![Code Climate](https://codeclimate.com/github/SmallLars/openssl-ccm.png)](https://codeclimate.com/github/SmallLars/openssl-ccm)
[![Inline docs](http://inch-ci.org/github/smalllars/openssl-ccm.png)](http://inch-ci.org/github/smalllars/openssl-ccm)

# openssl-ccm

Ruby Gem for [RFC 3610 - Counter with CBC-MAC (CCM)](http://tools.ietf.org/html/rfc3610)

## Installation

Add this line to your application's Gemfile:

    gem 'openssl-ccm'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install openssl-ccm

## Usage

Example:

    require 'openssl/ccm'
    ccm = OpenSSL::CCM.new('AES', 'My16Byte LongKey', 8)
    ciphertext = ccm.encrypt('The message to encrypt', 'The nonce')
    plaintext = ccm.decrypt(ciphertext, 'The nonce')

After initialisation, you can use the object as often you need.
