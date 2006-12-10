
create table hosts (
id SERIAL PRIMARY KEY,
address VARCHAR(16) UNIQUE,
comm VARCHAR(255),
name VARCHAR(255),
state VARCHAR(255),
info VARCHAR(1024)
);


create table services (
id SERIAL PRIMARY KEY,
host_id INTEGER,
port INTEGER NOT NULL,
proto VARCHAR(16) NOT NULL,
state VARCHAR(255),
name VARCHAR(255),
info VARCHAR(1024)
);


create table vulns (
id SERIAL PRIMARY KEY,
service_id INTEGER,
name VARCHAR(255),
data TEXT
);


create table refs (
id SERIAL PRIMARY KEY,
ref_id INTEGER,
name VARCHAR(512)
);


create table vulns_refs (
ref_id INTEGER,
vuln_id INTEGER
);
