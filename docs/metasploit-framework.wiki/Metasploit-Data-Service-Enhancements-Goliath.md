Project Goliath came about primarilly around the need to enhance the current data service and data models to increase the value of data in metasploit to our end users.

This work is currently being done in 2 stages:

**_Stage 1_**

This is currently a work in progress (which is why Goliath is currently not fully functional).
The work being done or already done include:
* Port of the current data models to be used over HTTP / HTTPS
* Creation of a web service that serves the metasploit data model
* Creation of a new command in metasploit to remote (web based) data services
* Creation of a Metasploit Data Service API V1 document

**_Stage 2_**
* Enhance the current data model
* Creation of a Metasploit Data Service API V2 document
  Potential Changes include (feel free to submit ideas):
  * Creation of a generic data type (for when you can't figure out which data type data belongs)


## Rationale

The current data storage mechanism couples the metasploit core framework code to the current data storage technology. Coupling causes inflexibility which are reflected via the following problems:
* Changes to the current data model are complex
* The ability to support/use different data storage technologies is difficult
* Promotes a monolithic architecture where poor performance in any segment of the software affects the entire system (large network scans)

Our solution to this is a data service proxy.  A data service proxy allows us to separate core Metasploit Framework code from the underlying data service technology.  The `framework.db` reference to data services is no longer tied directly to the underlying data storage, but instead all calls are proxied to an underlying implementation.

Currently we plan to support the legacy data storage technology stack (RAILS/PostgreSQL) which we hope to eventually phase out.  The new implementation will use a RESTful (https://en.wikipedia.org/wiki/Representational_state_transfer) approach whereby calls to `framework.db` can be proxied to a remote web service that supports the same data service API.  We have built a web service that runs atop the current data storage service for the community.

This approach enables us to:
* More easily enhance the Metasploit data model
* Run a web-based data service independent of the Metasploit Framework
    * Reduces the memory used by a Metasploit Framework instance using a data service by no longer requiring a DB client
    *  Increases throughput as storage calls don't necessarily need to be asynchronous
    *  Allow teams to collaborate easily by connecting to a centralized data service
* Quickly build out data services that leverage different technology stacks
* Isolate component testing
* Users of metasploit can now leverage a rigid API to build other tools easily (documentation to be provided soon)

## Usage

For more information on setting up the web service and using the data services see [[Metasploit Web Service|./Metasploit-Web-Service.md]].