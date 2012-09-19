#--
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 16 Jul 2006
# 
# See EventMachine and EventMachine::Connection for documentation and
# usage examples.
#
#----------------------------------------------------------------------------
#
# Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
# Gmail: blackhedd
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of either: 1) the GNU General Public License
# as published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version; or 2) Ruby's License.
# 
# See the file COPYING for complete licensing information.
#
#---------------------------------------------------------------------------
#
# 

=begin

Message Routing in EventMachine.

The goal here is to enable "routing points," objects that can send and receive
"messages," which are delimited streams of bytes. The boundaries of a message
are preserved as it passes through the reactor system.

There will be several module methods defined in EventMachine to create route-point
objects (which will probably have a base class of EventMachine::MessageRouter
until someone suggests a better name).

As with I/O objects, routing objects will receive events by having the router
core call methods on them. And of course user code can and will define handlers
to deal with events of interest.

The message router base class only really needs a receive_message method. There will
be an EM module-method to send messages, in addition to the module methods to create
the various kinds of message receivers.

The simplest kind of message receiver object can receive messages by being named 
explicitly in a parameter to EM#send_message. More sophisticated receivers can define
pub-sub selectors and message-queue names. And they can also define channels for
route-points in other processes or even on other machines.

A message is NOT a marshallable entity. Rather, it's a chunk of flat content more like
an Erlang message. Initially, all content submitted for transmission as a message will
have the to_s method called on it. Eventually, we'll be able to transmit certain structured
data types (XML and YAML documents, Structs within limits) and have them reconstructed
on the other end.

A fundamental goal of the message-routing capability is to interoperate seamlessly with
external systems, including non-Ruby systems like ActiveMQ. We will define various protocol
handlers for things like Stomp and possibly AMQP, but these will be wrapped up and hidden
from the users of the basic routing capability.

As with Erlang, a critical goal is for programs that are built to use message-passing to work
WITHOUT CHANGE when the code is re-based on a multi-process system.

=end

