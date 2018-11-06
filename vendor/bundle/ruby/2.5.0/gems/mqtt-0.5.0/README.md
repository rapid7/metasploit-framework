[![Build Status](https://travis-ci.org/njh/ruby-mqtt.svg)](https://travis-ci.org/njh/ruby-mqtt)

ruby-mqtt
=========

Pure Ruby gem that implements the [MQTT] protocol, a lightweight protocol for publish/subscribe messaging.

Also includes a class for parsing and generating [MQTT-SN] packets.


Table of Contents
-----------------
* [Installation](#installation)
* [Quick Start](#quick-start)
* [Library Overview](#library-overview)
* [Resources](#resources)
* [License](#license)
* [Contact](#contact)


Installation
------------

You may get the latest stable version from [Rubygems]:

    $ gem install mqtt

Alternatively, to use a development snapshot from GitHub using [Bundler]:

    gem 'mqtt', :git => 'https://github.com/njh/ruby-mqtt.git'


Quick Start
-----------

~~~ ruby
require 'rubygems'
require 'mqtt'

# Publish example
MQTT::Client.connect('test.mosquitto.org') do |c|
  c.publish('test', 'message')
end

# Subscribe example
MQTT::Client.connect('test.mosquitto.org') do |c|
  # If you pass a block to the get method, then it will loop
  c.get('test') do |topic,message|
    puts "#{topic}: #{message}"
  end
end
~~~


Library Overview
----------------

### Connecting ###

A new client connection can be created by passing either a [MQTT URI], a host and port or by passing a hash of attributes.

~~~ ruby
client = MQTT::Client.connect('mqtt://myserver.example.com')
client = MQTT::Client.connect('mqtts://user:pass@myserver.example.com')
client = MQTT::Client.connect('myserver.example.com')
client = MQTT::Client.connect('myserver.example.com', 18830)
client = MQTT::Client.connect(:host => 'myserver.example.com', :port => 1883 ... )
~~~

TLS/SSL is not enabled by default, to enabled it, pass ```:ssl => true```:

~~~ ruby
client = MQTT::Client.connect(
  :host => 'test.mosquitto.org',
  :port => 8883,
  :ssl => true
)
~~~

Alternatively you can create a new Client object and then configure it by setting attributes. This example shows setting up client certificate based authentication:

~~~ ruby
client = MQTT::Client.new
client.host = 'myserver.example.com'
client.ssl = true
client.cert_file = path_to('client.pem')
client.key_file  = path_to('client.key')
client.ca_file   = path_to('root-ca.pem')
client.connect()
~~~

The connection can either be made without the use of a block:

~~~ ruby
client = MQTT::Client.connect('test.mosquitto.org')
# perform operations
client.disconnect()
~~~

Or, if using a block, with an implicit disconnection at the end of the block.

~~~ ruby
MQTT::Client.connect('test.mosquitto.org') do |client|
  # perform operations
end
~~~

For more information, see and list of attributes for the [MQTT::Client] class and the [MQTT::Client.connect] method.


### Publishing ###

To send a message to a topic, use the ```publish``` method:

~~~ ruby
client.publish(topic, payload, retain=false)
~~~

The method will return once the message has been sent to the MQTT server.

For more information see the [MQTT::Client#publish] method.


### Subscribing ###

You can send a subscription request to the MQTT server using the subscribe method. One or more [Topic Filters] may be passed in:

~~~ ruby
client.subscribe( 'topic1' )
client.subscribe( 'topic1', 'topic2' )
client.subscribe( 'foo/#' )
~~~

For more information see the [MQTT::Client#subscribe] method.


### Receiving Messages ###

To receive a message, use the get method. This method will block until a message is available. The topic is the name of the topic the message was sent to. The message is a string:

~~~ ruby
topic,message = client.get
~~~

Alternatively, you can give the get method a block, which will be called for every message received and loop forever:

~~~ ruby
client.get do |topic,message|
  # Block is executed for every message received
end
~~~

For more information see the [MQTT::Client#get] method.


### Parsing and serialising of packets ###

The parsing and serialising of MQTT and MQTT-SN packets is a separate lower-level API.
You can use it to build your own clients and servers, without using any of the rest of the
code in this gem.

~~~ ruby
# Parse a string containing a binary packet into an object
packet_obj = MQTT::Packet.parse(binary_packet)
    
# Write a PUBACK packet to an IO handle
ios << MQTT::Packet::Puback(:id => 20)
    
# Write an MQTT-SN Publish packet with QoS -1 to a UDP socket
socket = UDPSocket.new
socket.connect('localhost', MQTT::SN::DEFAULT_PORT)
socket << MQTT::SN::Packet::Publish.new(
  :topic_id => 'TT',
  :topic_id_type => :short,
  :data => "The time is: #{Time.now}",
  :qos => -1
)
socket.close
~~~

Limitations
-----------

 * QoS 2 is not currently supported by client
 * Automatic re-connects to the server are not supported
 * No local persistence for packets


Resources
---------

* API Documentation: http://rubydoc.info/gems/mqtt
* Protocol Specification v3.1.1: http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html
* Protocol Specification v3.1: http://public.dhe.ibm.com/software/dw/webservices/ws-mqtt/mqtt-v3r1.html
* MQTT-SN Protocol Specification v1.2: http://mqtt.org/new/wp-content/uploads/2009/06/MQTT-SN_spec_v1.2.pdf
* MQTT Homepage: http://www.mqtt.org/
* GitHub Project: http://github.com/njh/ruby-mqtt


License
-------

The mqtt ruby gem is licensed under the terms of the MIT license.
See the file LICENSE for details.


Contact
-------

* Author:    Nicholas J Humfrey
* Email:     njh@aelius.com
* Twitter:   [@njh]
* Home Page: http://www.aelius.com/njh/



[@njh]:           http://twitter.com/njh
[MQTT]:           http://www.mqtt.org/
[MQTT-SN]:        http://mqtt.org/2013/12/mqtt-for-sensor-networks-mqtt-sn
[Rubygems]:       http://rubygems.org/
[Bundler]:        http://bundler.io/
[MQTT URI]:       https://github.com/mqtt/mqtt.github.io/wiki/URI-Scheme
[Topic Filters]:  http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html#_Toc388534397

[MQTT::Client]:           http://rubydoc.info/gems/mqtt/MQTT/Client#instance_attr_details
[MQTT::Client.connect]:   http://rubydoc.info/gems/mqtt/MQTT/Client.connect
[MQTT::Client#publish]:   http://rubydoc.info/gems/mqtt/MQTT/Client:publish
[MQTT::Client#subscribe]: http://rubydoc.info/gems/mqtt/MQTT/Client:subscribe
[MQTT::Client#get]:       http://rubydoc.info/gems/mqtt/MQTT/Client:get

