drop table hosts;
create table hosts (
'id' INTEGER PRIMARY KEY NOT NULL,
'address' VARCHAR(16) UNIQUE,
'comm' VARCHAR(255),
'name' VARCHAR(255),
'state' VARCHAR(255),
'desc' VARCHAR(1024)
);

drop table services;
create table services (
'id' INTEGER PRIMARY KEY NOT NULL,
'host_id' INTEGER,
'port' INTEGER NOT NULL,
'proto' VARCHAR(16) NOT NULL,
'state' VARCHAR(255),
'name' VARCHAR(255),
'desc' VARCHAR(1024)
);

drop table vulns;
create table vulns (
'id' INTEGER PRIMARY KEY NOT NULL,
'service_id' INTEGER,
'name' VARCHAR(1024),
'data' TEXT
);

drop table refs;
create table refs (
'id' INTEGER PRIMARY KEY NOT NULL,
'ref_id' INTEGER,
'name' VARCHAR(512)
);

drop table vulns_refs;
create table vulns_refs (
'ref_id' INTEGER,
'vuln_id' INTEGER
);


.schema

.exit
