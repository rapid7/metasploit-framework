# Ruby/NTLM -- NTLM Authentication Library for Ruby

[![Build Status](https://travis-ci.org/WinRb/rubyntlm.png)](https://travis-ci.org/WinRb/rubyntlm)

Ruby/NTLM provides message creator and parser for the NTLM authentication. 

__100% Ruby__

How to install
--------------

```ruby
require 'rubyntlm'
```

Simple Example
--------------

### Creating NTLM Type 1 message

```ruby
   t1 = Net::NTLM::Message::Type1.new()
```

### Parsing NTLM Type 2 message from server

```ruby
   t2 = Net::NTLM::Message.parse(message_from_server)
```

### Creating NTLM Type 3 message

```ruby
   t3 = t2.response({:user => 'user', :password => 'passwd'})
```

Support
-------

https://groups.google.com/forum/?fromgroups#!forum/rubyntlm

Contributing
------------
1. Fork it.
2. Create a branch (git checkout -b my_feature_branch)
3. Commit your changes (git commit -am "Added a sweet feature")
4. Push to the branch (git push origin my_feature_branch)
5. Create a pull requst from your branch into master (Please be sure to provide enough detail for us to cipher what this change is doing)
