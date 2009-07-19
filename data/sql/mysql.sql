
create table hosts (
id SERIAL PRIMARY KEY,
created TIMESTAMP,
address VARCHAR(16) UNIQUE,
comm VARCHAR(255),
name VARCHAR(255),
state VARCHAR(255),
info VARCHAR(1024),
os_name VARCHAR(255),
os_flavor VARCHAR(255),
os_sp VARCHAR(255),
os_lang VARCHAR(255),
arch VARCHAR(255)
);


create table services (
id SERIAL PRIMARY KEY,
host_id INTEGER,
created TIMESTAMP,
port INTEGER NOT NULL,
proto VARCHAR(16) NOT NULL,
state VARCHAR(255),
name VARCHAR(255),
info VARCHAR(1024)
);


create table vulns (
id SERIAL PRIMARY KEY,
service_id INTEGER,
created TIMESTAMP,
name VARCHAR(255),
data TEXT
);


create table refs (
id SERIAL PRIMARY KEY,
ref_id INTEGER,
created TIMESTAMP,
name VARCHAR(512)
);


create table vulns_refs (
ref_id INTEGER,
vuln_id INTEGER
);


create table notes (
id SERIAL PRIMARY KEY,
host_id INTEGER,
created TIMESTAMP,
ntype VARCHAR(512),
data TEXT
);
