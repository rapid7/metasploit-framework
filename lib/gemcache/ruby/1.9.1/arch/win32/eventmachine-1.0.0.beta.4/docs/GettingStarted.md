# @title Getting Started with Ruby EventMachine
# @markup markdown
# @author Michael S. Klishin, Dan Sinclair

# Getting started with Ruby EventMachine #


## About this guide ##

This guide is a quick tutorial that helps you to get started with EventMachine for writing event-driven
servers, clients and using it as a lightweight concurrency library.
It should take about 20 minutes to read and study the provided code examples. This guide covers

 * Installing EventMachine via [Rubygems](http://rubygems.org) and [Bundler](http://gembundler.com).
 * Building an Echo server, the "Hello, world"-like code example of network servers.
 * Building a simple chat, both server and client.
 * Building a very small asynchronous Websockets client.


## Covered versions ##

This guide covers EventMachine v0.12.10 and 1.0 (including betas).


## Level ##

This guide assumes you are comfortable (but not necessary a guru) with the command line. On Microsoft Windows™,
we recommend you to use [JRuby](http://jruby.org) when running these examples.


## Installing EventMachine ##

### Make sure you have Ruby installed ###

This guide assumes you have one of the supported Ruby implementations installed:

 * Ruby 1.8.7
 * Ruby 1.9.2
 * [JRuby](http://jruby.org) (we recommend 1.6)
 * [Rubinius](http://rubini.us) 1.2 or higher
 * [Ruby Enterprise Edition](http://www.rubyenterpriseedition.com)

EventMachine works on Microsoft Windows™.


### With Rubygems ###

To install the EventMachine gem do

    gem install eventmachine


### With Bundler ###

    gem "eventmachine"


### Verifying your installation ###

Lets verify your installation with this quick IRB session:

    irb -rubygems

    ruby-1.9.2-p180 :001 > require "eventmachine"
     => true
    ruby-1.9.2-p180 :002 > EventMachine::VERSION
     => "1.0.0.beta.3"


## An Echo Server Example ##

Lets begin with the classic "Hello, world"-like example, an echo server. The echo server responds clients with the
same data that was provided. First, here's the code:

{include:file:examples/guides/getting\_started/01\_eventmachine\_echo_server.rb}


When run, the server binds to port 10000. We can connect using Telnet and verify it's working:

    telnet localhost 10000

On my machine the output looks like:

    ~ telnet localhost 10000
    Trying 127.0.0.1...
    Connected to localhost.
    Escape character is '^]'.

Let's send something to our server. Type in "Hello, EventMachine" and hit Enter. The server will respond with
the same string:

    ~ telnet localhost 10000
    Trying 127.0.0.1...
    Connected to localhost.
    Escape character is '^]'.
    Hello, EventMachine
    # (here we hit Enter)
    Hello, EventMachine
    # (this ^^^ is our echo server reply)

It works! Congratulations, you now can tell your Node.js-loving friends that you "have done some event-driven programming, too".
Oh, and to stop Telnet, hit Control + Shift + ] and then Control + C.

Lets walk this example line by line and see what's going on. These lines

    require 'rubygems' # or use Bundler.setup
    require 'eventmachine'

probably look familiar: you use [RubyGems](http://rubygems.org) (or [Bundler](http://gembundler.com/)) for dependencies and then require EventMachine gem. Boring.

Next:

    class EchoServer < EventMachine::Connection
      def receive_data(data)
        send_data(data)
      end
    end

Is the implementation of our echo server. We define a class that inherits from {EventMachine::Connection}
and a handler (aka callback) for one event: when we receive data from a client.

EventMachine handles the connection setup, receiving data and passing it to our handler, {EventMachine::Connection#receive_data}.

Then we implement our protocol logic, which in the case of Echo is pretty trivial: we send back whatever we receive.
To do so, we're using {EventMachine::Connection#send_data}.

Lets modify the example to recognize `exit` command:

{include:file:examples/guides/getting\_started/02\_eventmachine\_echo_server\_that\_recognizes\_exit\_command.rb}

Our `receive\_data` changed slightly and now looks like this:

    def receive_data(data)
      if data.strip =~ /exit$/i
        EventMachine.stop_event_loop
      else
        send_data(data)
      end
    end

Because incoming data has trailing newline character, we strip it off before matching it against a simple regular
expression. If the data ends in `exit`, we stop EventMachine event loop with {EventMachine.stop_event_loop}. This unblocks
main thread and it finishes execution, and our little program exits as the result.

To summarize this first example:

 * Subclass {EventMachine::Connection} and override {EventMachine::Connection#send_data} to handle incoming data.
 * Use {EventMachine.run} to start EventMachine event loop and then bind echo server with {EventMachine.start_server}.
 * To stop the event loop, use {EventMachine.stop_event_loop} (aliased as {EventMachine.stop})

Lets move on to a slightly more sophisticated example that will introduce several more features and methods
EventMachine has to offer.


## A Simple Chat Server Example ##

Next we will write a simple chat. Initially clients will still use telnet to connect, but then we will add little
client application that will serve as a proxy between telnet and the chat server. This example is certainly longer
(~ 150 lines with whitespace and comments) so instead of looking at the final version and going through it line by line,
we will instead begin with a very simple version that only keeps track of connected clients and then add features
as we go.

To set some expectations about our example:

 * It will keep track of connected clients
 * It will support a couple of commands, à la IRC
 * It will support direct messages using Twitter-like @usernames
 * It won't use MongoDB, fibers or distributed map/reduce for anything but will be totally [Web Scale™](http://bit.ly/webscaletm) nonetheless. Maybe even [ROFLscale](http://bit.ly/roflscalevideo).

### Step one: detecting connections and disconnectons ###

First step looks like this:

{include:file:examples/guides/getting\_started/04\_simple\_chat\_server\_step\_one.rb}

We see familiar {EventMachine.run} and {EventMachine.start_server}, but also {EventMachine::Connection#post_init} and {EventMachine::Connection#unbind} we haven't
met yet. We don't use them in this code, so when are they run? Like {EventMachine::Connection#receive_data}, these methods are callbacks. EventMachine calls them
when certain events happen:

 * {EventMachine#post_init} is called by the event loop immediately after the network connection has been established.
   In the chat server example case, this is when a new client connects.
 * {EventMachine#unbind} is called when client disconnects, connection is closed or is lost (because of a network issue, for example).

All our chat server does so far is logging connections or disconnections. What we want it to do next is to keep track of connected clients.


### Step two: keep track of connected clients ###

Next iteration of the code looks like this:

{include:file:examples/guides/getting\_started/05\_simple\_chat\_server\_step\_two.rb}

While the code we added is very straightforward, we have to clarify one this first: subclasses of {EventMachine::Connection} are instantiated by
EventMachine for every new connected peer. So for 10 connected chat clients, there will be 10 separate `SimpleChatServer` instances in our
server process. Like any other objects, they can be stored in a collection, can provide public API other objects use, can instantiate or inject
dependencies and in general live a happy life all Ruby objects live until garbage collection happens.

In the example above we use a @@class_variable to keep track of connected clients. In Ruby, @@class variables are accessible from instance
methods so we can add new connections to the list from `SimpleChatServer#post_init` and remove them in `SimpleChatServer#unbind`. We can also
filter connections by some criteria, as `SimpleChatServer#other_peers demonstrates`.

So, we keep track of connections but how do we identify them? For a chat app, it's pretty common to use usernames for that. Lets ask our clients
to enter usernames when they connect.


### Step three: adding usernames ##

To add usernames, we need to add a few things:

 * We need to invite newly connected clients to enter their username.
 * A reader (getter) method on our {EventMachine::Connection} subclass.
 * An idea of connection state (keeping track of whether a particular participant had entered username before).

Here is one way to do it:

{include:file:examples/guides/getting\_started/06\_simple\_chat\_server\_step\_three.rb}

This is quite an update so lets take a look at each method individually. First, `SimpleChatServer#post_init`:

    def post_init
      @username = nil
      puts "A client has connected..."
      ask_username
    end

To keep track of username we ask chat participants for, we add @username instance variable to our connection class. Connection
instances are just Ruby objects associated with a particular connected peer, so using @ivars is very natural. To make username
value accessible to other objects, we added a reader method that was not shown on the snippet above.

Lets dig into `SimpleChatServer#ask_username`:

    def ask_username
      self.send_line("[info] Enter your username:")
    end # ask_username

    # ...

    def send_line(line)
      self.send_data("#{line}\n")
    end # send_line(line)

Nothing new here, we are using {EventMachine::Connection#send_data} which we have seen before.


In `SimpleChatServer#receive_data` we now have to check if the username was entered or we need
to ask for it:

    def receive_data(data)
      if entered_username?
        handle_chat_message(data.strip)
      else
        handle_username(data.strip)
      end
    end

    # ...

    def entered_username?
      !@username.nil? && !@username.empty?
    end # entered_username?

Finally, handler of chat messages is not yet implemented:

    def handle_chat_message(msg)
      raise NotImplementedError
    end

Lets try this example out using Telnet:

    ~ telnet localhost 10000
    Trying 127.0.0.1...
    Connected to localhost.
    Escape character is '^]'.
    [info] Enter your username:
    antares_
    [info] Ohai, antares_

and the server output:

    A client has connected...
    antares_ has joined

This version requires you to remember how to terminate your Telnet session (Ctrl + Shift + ], then Ctrl + C).
It is annoying, so why don't we add the same `exit` command to our chat server?


### Step four: adding exit command and delivering chat messages ####

{include:file:examples/guides/getting\_started/07\_simple\_chat\_server\_step\_four.rb}

TBD

Lets test-drive this version. Client A:

    ~ telnet localhost 10000
    Trying 127.0.0.1...
    Connected to localhost.
    Escape character is '^]'.
    [info] Enter your username:
    michael
    [info] Ohai, michael
    Hi everyone
    michael: Hi everyone
    joe has joined the room
    # here ^^^ client B connects, lets greet him
    hi joe
    michael: hi joe
    joe: hey michael
    # ^^^ client B replies
    exit
    # ^^^ out command in action
    Connection closed by foreign host.

Client B:

    ~ telnet localhost 10000
    Trying 127.0.0.1...
    Connected to localhost.
    Escape character is '^]'.
    [info] Enter your username:
    joe
    [info] Ohai, joe
    michael: hi joe
    # ^^^ client A greets us, lets reply
    hey michael
    joe: hey michael
    exit
    # ^^^ out command in action
    Connection closed by foreign host.

And finally, the server output:

    A client has connected...
    michael has joined
    A client has connected...
    _antares has joined
    [info] _antares has left
    [info] michael has left

Our little char server now supports usernames, sending messages and the `exit` command. Next up, private (aka direct) messages.


### Step five: adding direct messages and one more command ###

To add direct messages, we come up with a simple convention: private messages begin with @username and may have optional colon before
message text, like this:

    @joe: hey, how do you like eventmachine?

This convention makes parsing of messages simple so that we can concentrate on delivering them to a particular client connection.
Remember when we added `username` reader on our connection class? That tiny change makes this step possible: when a new direct
message comes in, we extract username and message text and then find then connection for @username in question:

    #
    # Message handling
    #
  
    def handle_chat_message(msg)
      if command?(msg)
        self.handle_command(msg)
      else
        if direct_message?(msg)
          self.handle_direct_message(msg)
        else
          self.announce(msg, "#{@username}:")
        end
      end
    end # handle_chat_message(msg)
  
    def direct_message?(input)
      input =~ DM_REGEXP
    end # direct_message?(input)
  
    def handle_direct_message(input)
      username, message = parse_direct_message(input)
  
      if connection = @@connected_clients.find { |c| c.username == username }
        puts "[dm] @#{@username} => @#{username}"
        connection.send_line("[dm] @#{@username}: #{message}")
      else
        send_line "@#{username} is not in the room. Here's who is: #{usernames.join(', ')}"
      end
    end # handle_direct_message(input)
  
    def parse_direct_message(input)
      return [$1, $2] if input =~ DM_REGEXP
    end # parse_direct_message(input)

This snippet demonstrates how one connection instance can obtain another connection instance and send data to it.
This is a very powerful feature, consider just a few use cases:

 * Peer-to-peer protocols
 * Content-aware routing
 * Efficient streaming with optional filtering

Less common use cases include extending C++ core of EventMachine to provide access to  hardware that streams events that
can be re-broadcasted to any interested parties connected via TCP, UDP or something like AMQP or WebSockets. With this,
sky is the limit. Actually, EventMachine has several features for efficient proxying data between connections.
We will not cover them in this guide.

One last feature that we are going to add to our chat server is the `status` command that tells you current server time and how many people
are there in the chat room:

    #
    # Commands handling
    #
  
    def command?(input)
      input =~ /(exit|status)$/i
    end # command?(input)
  
    def handle_command(cmd)
      case cmd
      when /exit$/i   then self.close_connection
      when /status$/i then self.send_line("[chat server] It's #{Time.now.strftime('%H:%M')} and there are #{self.number_of_connected_clients} people in the room")
      end
    end # handle_command(cmd)

Hopefully this piece of code is easy to follow. Try adding a few more commands, for example, the `whoishere` command that lists people
currently in the chat room.

In the end, our chat server looks like this:

{include:file:examples/guides/getting\_started/08\_simple\_chat\_server\_step\_five.rb}

We are almost done with the server but there are some closing thoughts.


### Step six: final version ###

Just in case, here is the final version of the chat server code we have built:

{include:file:examples/guides/getting\_started/03\_simple\_chat\_server.rb}


### Step seven: future directions and some closing thoughts ###

The chat server is just about 150 lines of Ruby including empty lines and comments, yet it has a few features most of chat server
examples never add. We did not, however, implement many other features that popular IRC clients like [Colloquy](http://colloquy.info) have:

 * Chat moderation
 * Multiple rooms
 * Connection timeout detection

How would one go about implementing them? We thought it is worth discussing what else EventMachine has to offer and what ecosystem projects
one can use to build a really feature-rich Web-based IRC chat client.

With multiple rooms it's more or less straightforward, just add one more hash and a bunch of commands and use the information about which rooms participant
is in when you are delivering messages. There is nothing in EventMachine itself that can make the job much easier for developer.

To implement chat moderation feature you may want to do a few things:

 * Work with client IP addresses. Maybe we want to consider everyone who connects from certain IPs a moderator.
 * Access persistent data about usernames of moderators and their credentials.

Does EventMachine have anything to offer here? It does. To obtain peer IP address, take a look at {EventMachine::Connection#get_peername}. The name of this method is
a little bit misleading and originates from low-level socket programming APIs.

#### A whirlwind tour of the EventMachine ecosystem ####

To work with data stores you can use several database drivers that ship with EventMachine itself, however, quite often there are some 3rd party projects in
the EventMachine ecosystem that have more features, are faster or just better maintained. So we figured it will be helpful to provide a few pointers
to some of those projects:

 * For MySQL, check out [em-mysql](https://github.com/eventmachine/em-mysql) project.
 * For PostgreSQL, have a look at Mike Perham's [EventMachine-based PostgreSQL driver](https://github.com/mperham/em_postgresql).
 * For Redis, there is a young but already popular [em-hiredis](https://github.com/mloughran/em-hiredis) library that combines EventMachine's non-blocking I/O with
   extreme performance of the official Redis C client, [hiredis](https://github.com/antirez/hiredis).
 * For MongoDB, see [em-mongo](https://github.com/bcg/em-mongo)
 * For Cassandra, Mike Perham [added transport agnosticism feature](http://www.mikeperham.com/2010/02/09/cassandra-and-eventmachine/) to the [cassandra gem](https://rubygems.org/gems/cassandra).

[Riak](http://www.basho.com/products_riak_overview.php) and CouchDB talk HTTP so it's possible to use [em-http-request](https://github.com/igrigorik/em-http-request).
If you are aware of EventMachine-based non-blocking drivers for these databases, as well as for HBase, let us know on the [EventMachine mailing list](http://groups.google.com/group/eventmachine).
Also, EventMachine supports TLS (aka SSL) and works well on [JRuby](http://jruby.org) and Windows.

Learn more in our {file:docs/Ecosystem.md EventMachine ecosystem} and {file:docs/TLS.md TLS (aka SSL)} guides.


#### Connection loss detection ####

Finally, connection loss detection. When our chat participant closes her laptop lid, how do we know that she is no longer active? The answer is, when EventMachine
detects TCP connectin closure, it calls {EventMachine::Connection#unbind}. Version 1.0.beta3 and later also pass an optional argument to that method. The argument
indicates what error (if any) caused the connection to be closed.

Learn more in our {file:docs/ConnectionFailureAndRecovery.md Connection Failure and Recovery} guide.


#### What the Chat Server Example doesn't demonstrate ####

This chat server also leaves out something production quality clients and servers must take care of: buffering. We intentionally did not include any buffering in
our chat server example: it would only distract you from learning what you really came here to learn: how to use EventMachine to build blazing fast asynchronous
networking programs quickly. However, {EventMachine::Connection#receive_data} does not offer any guarantees that you will be receiving "whole messages" all the time,
largely because the underlying transport (UDP or TCP) does not offer such guarantees. Many protocols, for example, AMQP, mandate that large content chunks are
split into smaller _frames_ of certain size. This means that [amq-client](https://github.com/ruby-amqp/amq-client) library, for instance, that has EventMachine-based driver,
has to deal with figuring out when exactly we received "the whole message". To do so, it uses buffering and employs various checks to detect _frame boundaries_.
So **don't be deceived by the simplicity of this chat example**: it intentionally leaves framing out, but real world protocols usually require it.



## A (Proxying) Chat Client Example ##

TBD


## Wrapping up ##

This tutorial ends here. Congratulations! You have learned quite a bit about EventMachine.


## What to read next ##

The documentation is organized as a {file:docs/DocumentationGuidesIndex.md number of guides}, covering all kinds of
topics. TBD


## Tell us what you think! ##

Please take a moment and tell us what you think about this guide on the [EventMachine mailing list](http://bit.ly/jW3cR3)
or in the #eventmachine channel on irc.freenode.net: what was unclear? What wasn't covered?
Maybe you don't like the guide style or the grammar and spelling are incorrect? Reader feedback is
key to making documentation better.
