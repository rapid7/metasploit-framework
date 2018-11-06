Ruby MQTT NEWS
==============

Ruby MQTT Version 0.5.0 (2016-04-16)
------------------------------------

* Switched default protocol version to 3.1.1
* Added support for Server Name Identification (SNI)
* Fix for unescaping user/password in URI
* Fix for bug in MQTT::Proxy class
* Add the ability to ignore retained packets when subscribed.
* Fix problem of wrong Puback packet ID
* Don't keepalive ping if disconnected
* Immediately close socket after failed Connack
* FakeServer improvements
* Fix for working with mathn library.


Ruby MQTT Version 0.4.0 (2016-06-27)
------------------------------------

* Added puback handling for QoS level 1
* Low-level MQTT-SN packet parsing support
* Allow certs to be set directly instead of just by file
* Allow keyphrase for certs to be passed through
* Put 'disconnect' inside an 'ensure' block
* Fix for error on publish with frozen payload
* Fix for packets always getting id 1
* Improvements to tests


Ruby MQTT Version 0.3.1 (2014-10-10)
------------------------------------

* Added ```last_ping_response``` to attribute to ```MQTT::Client```


Ruby MQTT Version 0.3.0 (2014-08-26)
------------------------------------

* Added support for MQTT protocol version 3.1.1
* Renamed a number of methods/attributes:
  - Renamed ```:granted_qos``` to ```:return_codes```
  - Renamed ```:remote_port``` to ```:port```
  - Renamed ```:remote_host``` to ```:host```
  - Renamed ```:message_id``` to ```:id```
  - Renamed ```:protocol_version``` to ```:protocol_level```
  - Renamed ```MQTT_BROKER``` environment variable to ```MQTT_SERVER```
* Added more checks to ensure that the 3.1.1 protocol specs are adhered to
* Added a Library Overview section to the README
* Added links to the protocol specification to README
* Improvements to the YARD API documentation
* Don't display payload in inspect if it contains non-visible ASCII characters
* Upgraded to rspec 3
* Various minor bug fixes and corrections


Ruby MQTT Version 0.2.0 (2014-04-02)
------------------------------------

* Added SSL/TLS support
* Added support for passing connection details using a URI
* Added support for using the ```MQTT_BROKER``` environment variable
* Allow passing array of topics to Client#unsubscribe
* Allow more combinations of arguments to be passed to a new Client
* No longer defaults to ‘localhost’ if there is no server configured
* Fixed more 'unused variable' warnings
* Documentation improvements
* Ruby 1.8 fixes
* Ruby 2 fixes


Ruby MQTT Version 0.1.0 (2013-09-07)
------------------------------------

* Changed license to MIT, to simplify licensing concerns
* Improvements for UTF-8 handling under Ruby 1.9
* Added ```get_packet``` method
* Added support for a keep-alive value of 0
* Added a #inspect method to the Packet classes
* Added checks for the protocol name and version
* Added check to ensure that packet body isn't too big
* Added validation of QoS value
* Added example of using authentication
* Fixed 'unused variable' warnings
* Reduced duplicated code in packet parsing
* Improved testing
  - Created fake server and integration tests
  - Better test coverage
  - Added more tests for error states


Ruby MQTT Version 0.0.9 (2012-12-21)
------------------------------------

* Fixes for Ruby 1.9.3 by Mike English
* Fix for ```client_id``` typo by Anubisss
* Added methods to inspect the incoming message queue: ```queue_empty?``` and ```queue_length```
* Fixed incorrect implementation of the parsing and serialising of Subscription Acknowledgement packets
* Changed test mocking from Mocha to rspec-mocks


Ruby MQTT Version 0.0.8 (2011-02-04)
------------------------------------

* Implemented Last Will and Testament feature
* Renamed dup attribute to duplicate to avoid method name clash
* Made the random ```client_id``` generator a public class method


Ruby MQTT Version 0.0.7 (2011-01-19)
------------------------------------

* You can now pass a topic and block to client.get
* Added MQTT::Client.connect class method


Ruby MQTT Version 0.0.5 (2011-01-18)
------------------------------------

* Implemented setting username and password (MQTT 3.1)
* Renamed ```clean_start``` to ``clean_session```
* Started using autoload to load classes
* Modernised Gem building mechanisms


Ruby MQTT Version 0.0.4 (2009-02-22)
------------------------------------

* Re-factored packet encoding/decoding into one class per packet type
* Added MQTT::Proxy class for implementing an MQTT proxy


Ruby MQTT Version 0.0.3 (2009-02-08)
------------------------------------

* Added checking of Connection Acknowledgement
* Automatic client identifier generation


Ruby MQTT Version 0.0.2 (2009-02-03)
------------------------------------

* Added support for packets longer than 127 bytes


Ruby MQTT Version 0.0.1 (2009-02-01)
------------------------------------

* Initial Release
