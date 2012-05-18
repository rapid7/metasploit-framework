# About EventMachine #


## What is EventMachine ##

EventMachine is an event-driven I/O and lightweight concurrency library for Ruby.
It provides event-driven I/O using the [Reactor pattern](http://en.wikipedia.org/wiki/Reactor_pattern),
much like [JBoss Netty](http://www.jboss.org/netty), [Apache MINA](http://mina.apache.org/),
Python's [Twisted](http://twistedmatrix.com), [Node.js](http://nodejs.org), libevent and libev.

EventMachine is designed to simultaneously meet two key needs:

 * Extremely high scalability, performance and stability for the most demanding production environments.
 * An API that eliminates the complexities of high-performance threaded network programming,
   allowing engineers to concentrate on their application logic.

This unique combination makes EventMachine a premier choice for designers of critical networked
applications, including Web servers and proxies, email and IM production systems, authentication/authorization
processors, and many more.

EventMachine has been around since the early 2000s and is a mature and battle tested library.


## What EventMachine is good for? ##

 * Scalable event-driven servers. Examples: [Thin](http://code.macournoyer.com/thin/) or [Goliath](https://github.com/postrank-labs/goliath/).
 * Scalable asynchronous clients for various protocols, RESTful APIs and so on. Examples: [em-http-request](https://github.com/igrigorik/em-http-request) or [amqp gem](https://github.com/ruby-amqp/amqp).
 * Efficient network proxies with custom logic. Examples: [Proxymachine](https://github.com/mojombo/proxymachine/).
 * File and network monitoring tools. Examples: [eventmachine-tail](https://github.com/jordansissel/eventmachine-tail) and [logstash](https://github.com/logstash/logstash).



## What platforms are supported by EventMachine? ##

EventMachine supports Ruby 1.8.7, 1.9.2, REE, JRuby and **works well on Windows** as well
as many operating systems from the Unix family (Linux, Mac OS X, BSD flavors).



## Install the gem ##

Install it with [RubyGems](https://rubygems.org/)

    gem install eventmachine

or add this to your Gemfile if you use [Bundler](http://gembundler.com/):

    gem "eventmachine"



## Getting started ##

For an introduction to EventMachine, check out:

 * [blog post about EventMachine by Ilya Grigorik](http://www.igvita.com/2008/05/27/ruby-eventmachine-the-speed-demon/).
 * [EventMachine Introductions by Dan Sinclair](http://everburning.com/news/eventmachine-introductions/).


### Server example: Echo server ###

Here's a fully-functional echo server written with EventMachine:

     require 'eventmachine'

     module EchoServer
       def post_init
         puts "-- someone connected to the echo server!"
       end

       def receive_data data
         send_data ">>>you sent: #{data}"
         close_connection if data =~ /quit/i
       end

       def unbind
         puts "-- someone disconnected from the echo server!"
      end
    end

    # Note that this will block current thread.
    EventMachine.run {
      EventMachine.start_server "127.0.0.1", 8081, EchoServer
    }


## EventMachine documentation ##

Currently we only have [reference documentation](http://eventmachine.rubyforge.org) and a [wiki](https://github.com/eventmachine/eventmachine/wiki).


## Community and where to get help ##

 * Join the [mailing list](http://groups.google.com/group/eventmachine) (Google Group)
 * Join IRC channel #eventmachine on irc.freenode.net


## License and copyright ##

EventMachine is copyrighted free software made available under the terms
of either the GPL or Ruby's License.

Copyright: (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.


## Alternatives ##

If you are unhappy with EventMachine and want to use Ruby, check out [Cool.io](http://coolio.github.com/).
One caveat: by May 2011, it did not support JRuby and Windows.
