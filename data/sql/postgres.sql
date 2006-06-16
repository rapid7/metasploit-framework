drop table hosts;

create table hosts (
id INTEGER PRIMARY KEY NOT NULL,
address VARCHAR(16) UNIQUE,
comm VARCHAR(255),
name VARCHAR(255),
state VARCHAR(255),
info VARCHAR(1024)
);

drop table services;

create table services (
id INTEGER PRIMARY KEY NOT NULL,
host_id INTEGER,
port INTEGER NOT NULL,
proto VARCHAR(16) NOT NULL,
state VARCHAR(255),
name VARCHAR(255),
info VARCHAR(1024)
);

drop table vulns;

create table vulns (
id INTEGER PRIMARY KEY NOT NULL,
service_id INTEGER,
name VARCHAR(255),
data TEXT
);

