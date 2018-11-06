--
-- PostgreSQL database dump
--

-- Dumped from database version 9.6.1
-- Dumped by pg_dump version 9.6.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


SET search_path = public, pg_catalog;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE api_keys (
    id integer NOT NULL,
    token text,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: api_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE api_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: api_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE api_keys_id_seq OWNED BY api_keys.id;


--
-- Name: automatic_exploitation_match_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE automatic_exploitation_match_results (
    id integer NOT NULL,
    match_id integer,
    run_id integer,
    state character varying NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: automatic_exploitation_match_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE automatic_exploitation_match_results_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: automatic_exploitation_match_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE automatic_exploitation_match_results_id_seq OWNED BY automatic_exploitation_match_results.id;


--
-- Name: automatic_exploitation_match_sets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE automatic_exploitation_match_sets (
    id integer NOT NULL,
    workspace_id integer,
    user_id integer,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: automatic_exploitation_match_sets_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE automatic_exploitation_match_sets_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: automatic_exploitation_match_sets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE automatic_exploitation_match_sets_id_seq OWNED BY automatic_exploitation_match_sets.id;


--
-- Name: automatic_exploitation_matches; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE automatic_exploitation_matches (
    id integer NOT NULL,
    module_detail_id integer,
    state character varying,
    nexpose_data_vulnerability_definition_id integer,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    match_set_id integer,
    matchable_type character varying,
    matchable_id integer,
    module_fullname text
);


--
-- Name: automatic_exploitation_matches_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE automatic_exploitation_matches_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: automatic_exploitation_matches_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE automatic_exploitation_matches_id_seq OWNED BY automatic_exploitation_matches.id;


--
-- Name: automatic_exploitation_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE automatic_exploitation_runs (
    id integer NOT NULL,
    workspace_id integer,
    user_id integer,
    match_set_id integer,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: automatic_exploitation_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE automatic_exploitation_runs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: automatic_exploitation_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE automatic_exploitation_runs_id_seq OWNED BY automatic_exploitation_runs.id;


--
-- Name: clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE clients (
    id integer NOT NULL,
    host_id integer,
    created_at timestamp without time zone,
    ua_string character varying(1024) NOT NULL,
    ua_name character varying(64),
    ua_ver character varying(32),
    updated_at timestamp without time zone
);


--
-- Name: clients_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE clients_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: clients_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE clients_id_seq OWNED BY clients.id;


--
-- Name: credential_cores_tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE credential_cores_tasks (
    core_id integer,
    task_id integer
);


--
-- Name: credential_logins_tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE credential_logins_tasks (
    login_id integer,
    task_id integer
);


--
-- Name: creds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE creds (
    id integer NOT NULL,
    service_id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    "user" character varying(2048),
    pass character varying(4096),
    active boolean DEFAULT true,
    proof character varying(4096),
    ptype character varying(256),
    source_id integer,
    source_type character varying
);


--
-- Name: creds_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE creds_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: creds_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE creds_id_seq OWNED BY creds.id;


--
-- Name: events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE events (
    id integer NOT NULL,
    workspace_id integer,
    host_id integer,
    created_at timestamp without time zone,
    name character varying,
    updated_at timestamp without time zone,
    critical boolean,
    seen boolean,
    username character varying,
    info text
);


--
-- Name: events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE events_id_seq OWNED BY events.id;


--
-- Name: exploit_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE exploit_attempts (
    id integer NOT NULL,
    host_id integer,
    service_id integer,
    vuln_id integer,
    attempted_at timestamp without time zone,
    exploited boolean,
    fail_reason character varying,
    username character varying,
    module text,
    session_id integer,
    loot_id integer,
    port integer,
    proto character varying,
    fail_detail text
);


--
-- Name: exploit_attempts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE exploit_attempts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: exploit_attempts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE exploit_attempts_id_seq OWNED BY exploit_attempts.id;


--
-- Name: exploited_hosts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE exploited_hosts (
    id integer NOT NULL,
    host_id integer NOT NULL,
    service_id integer,
    session_uuid character varying(8),
    name character varying(2048),
    payload character varying(2048),
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: exploited_hosts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE exploited_hosts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: exploited_hosts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE exploited_hosts_id_seq OWNED BY exploited_hosts.id;


--
-- Name: host_details; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE host_details (
    id integer NOT NULL,
    host_id integer,
    nx_console_id integer,
    nx_device_id integer,
    src character varying,
    nx_site_name character varying,
    nx_site_importance character varying,
    nx_scan_template character varying,
    nx_risk_score double precision
);


--
-- Name: host_details_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE host_details_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: host_details_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE host_details_id_seq OWNED BY host_details.id;


--
-- Name: hosts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE hosts (
    id integer NOT NULL,
    created_at timestamp without time zone,
    address inet NOT NULL,
    mac character varying,
    comm character varying,
    name character varying,
    state character varying,
    os_name character varying,
    os_flavor character varying,
    os_sp character varying,
    os_lang character varying,
    arch character varying,
    workspace_id integer NOT NULL,
    updated_at timestamp without time zone,
    purpose text,
    info character varying(65536),
    comments text,
    scope text,
    virtual_host text,
    note_count integer DEFAULT 0,
    vuln_count integer DEFAULT 0,
    service_count integer DEFAULT 0,
    host_detail_count integer DEFAULT 0,
    exploit_attempt_count integer DEFAULT 0,
    cred_count integer DEFAULT 0,
    detected_arch character varying,
    os_family character varying
);


--
-- Name: hosts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE hosts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: hosts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE hosts_id_seq OWNED BY hosts.id;


--
-- Name: hosts_tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE hosts_tags (
    host_id integer,
    tag_id integer,
    id integer NOT NULL
);


--
-- Name: hosts_tags_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE hosts_tags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: hosts_tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE hosts_tags_id_seq OWNED BY hosts_tags.id;


--
-- Name: listeners; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE listeners (
    id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    workspace_id integer DEFAULT 1 NOT NULL,
    task_id integer,
    enabled boolean DEFAULT true,
    owner text,
    payload text,
    address text,
    port integer,
    options bytea,
    macro text
);


--
-- Name: listeners_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE listeners_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: listeners_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE listeners_id_seq OWNED BY listeners.id;


--
-- Name: loots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE loots (
    id integer NOT NULL,
    workspace_id integer DEFAULT 1 NOT NULL,
    host_id integer,
    service_id integer,
    ltype character varying(512),
    path character varying(1024),
    data text,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    content_type character varying,
    name text,
    info text,
    module_run_id integer
);


--
-- Name: loots_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE loots_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: loots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE loots_id_seq OWNED BY loots.id;


--
-- Name: macros; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE macros (
    id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    owner text,
    name text,
    description text,
    actions bytea,
    prefs bytea
);


--
-- Name: macros_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE macros_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: macros_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE macros_id_seq OWNED BY macros.id;


--
-- Name: metasploit_credential_cores; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE metasploit_credential_cores (
    id integer NOT NULL,
    origin_id integer NOT NULL,
    origin_type character varying NOT NULL,
    private_id integer,
    public_id integer,
    realm_id integer,
    workspace_id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    logins_count integer DEFAULT 0
);


--
-- Name: metasploit_credential_cores_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE metasploit_credential_cores_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metasploit_credential_cores_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE metasploit_credential_cores_id_seq OWNED BY metasploit_credential_cores.id;


--
-- Name: metasploit_credential_logins; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE metasploit_credential_logins (
    id integer NOT NULL,
    core_id integer NOT NULL,
    service_id integer NOT NULL,
    access_level character varying,
    status character varying NOT NULL,
    last_attempted_at timestamp without time zone,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: metasploit_credential_logins_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE metasploit_credential_logins_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metasploit_credential_logins_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE metasploit_credential_logins_id_seq OWNED BY metasploit_credential_logins.id;


--
-- Name: metasploit_credential_origin_cracked_passwords; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE metasploit_credential_origin_cracked_passwords (
    id integer NOT NULL,
    metasploit_credential_core_id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: metasploit_credential_origin_cracked_passwords_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE metasploit_credential_origin_cracked_passwords_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metasploit_credential_origin_cracked_passwords_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE metasploit_credential_origin_cracked_passwords_id_seq OWNED BY metasploit_credential_origin_cracked_passwords.id;


--
-- Name: metasploit_credential_origin_imports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE metasploit_credential_origin_imports (
    id integer NOT NULL,
    filename text NOT NULL,
    task_id integer,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: metasploit_credential_origin_imports_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE metasploit_credential_origin_imports_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metasploit_credential_origin_imports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE metasploit_credential_origin_imports_id_seq OWNED BY metasploit_credential_origin_imports.id;


--
-- Name: metasploit_credential_origin_manuals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE metasploit_credential_origin_manuals (
    id integer NOT NULL,
    user_id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: metasploit_credential_origin_manuals_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE metasploit_credential_origin_manuals_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metasploit_credential_origin_manuals_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE metasploit_credential_origin_manuals_id_seq OWNED BY metasploit_credential_origin_manuals.id;


--
-- Name: metasploit_credential_origin_services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE metasploit_credential_origin_services (
    id integer NOT NULL,
    service_id integer NOT NULL,
    module_full_name text NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: metasploit_credential_origin_services_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE metasploit_credential_origin_services_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metasploit_credential_origin_services_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE metasploit_credential_origin_services_id_seq OWNED BY metasploit_credential_origin_services.id;


--
-- Name: metasploit_credential_origin_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE metasploit_credential_origin_sessions (
    id integer NOT NULL,
    post_reference_name text NOT NULL,
    session_id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: metasploit_credential_origin_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE metasploit_credential_origin_sessions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metasploit_credential_origin_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE metasploit_credential_origin_sessions_id_seq OWNED BY metasploit_credential_origin_sessions.id;


--
-- Name: metasploit_credential_privates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE metasploit_credential_privates (
    id integer NOT NULL,
    type character varying NOT NULL,
    data text NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    jtr_format character varying
);


--
-- Name: metasploit_credential_privates_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE metasploit_credential_privates_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metasploit_credential_privates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE metasploit_credential_privates_id_seq OWNED BY metasploit_credential_privates.id;


--
-- Name: metasploit_credential_publics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE metasploit_credential_publics (
    id integer NOT NULL,
    username character varying NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    type character varying NOT NULL
);


--
-- Name: metasploit_credential_publics_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE metasploit_credential_publics_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metasploit_credential_publics_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE metasploit_credential_publics_id_seq OWNED BY metasploit_credential_publics.id;


--
-- Name: metasploit_credential_realms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE metasploit_credential_realms (
    id integer NOT NULL,
    key character varying NOT NULL,
    value character varying NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: metasploit_credential_realms_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE metasploit_credential_realms_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: metasploit_credential_realms_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE metasploit_credential_realms_id_seq OWNED BY metasploit_credential_realms.id;


--
-- Name: mod_refs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE mod_refs (
    id integer NOT NULL,
    module character varying(1024),
    mtype character varying(128),
    ref text
);


--
-- Name: mod_refs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE mod_refs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mod_refs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE mod_refs_id_seq OWNED BY mod_refs.id;


--
-- Name: module_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE module_actions (
    id integer NOT NULL,
    detail_id integer,
    name text
);


--
-- Name: module_actions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE module_actions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: module_actions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE module_actions_id_seq OWNED BY module_actions.id;


--
-- Name: module_archs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE module_archs (
    id integer NOT NULL,
    detail_id integer,
    name text
);


--
-- Name: module_archs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE module_archs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: module_archs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE module_archs_id_seq OWNED BY module_archs.id;


--
-- Name: module_authors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE module_authors (
    id integer NOT NULL,
    detail_id integer,
    name text,
    email text
);


--
-- Name: module_authors_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE module_authors_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: module_authors_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE module_authors_id_seq OWNED BY module_authors.id;


--
-- Name: module_details; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE module_details (
    id integer NOT NULL,
    mtime timestamp without time zone,
    file text,
    mtype character varying,
    refname text,
    fullname text,
    name text,
    rank integer,
    description text,
    license character varying,
    privileged boolean,
    disclosure_date timestamp without time zone,
    default_target integer,
    default_action text,
    stance character varying,
    ready boolean
);


--
-- Name: module_details_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE module_details_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: module_details_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE module_details_id_seq OWNED BY module_details.id;


--
-- Name: module_mixins; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE module_mixins (
    id integer NOT NULL,
    detail_id integer,
    name text
);


--
-- Name: module_mixins_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE module_mixins_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: module_mixins_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE module_mixins_id_seq OWNED BY module_mixins.id;


--
-- Name: module_platforms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE module_platforms (
    id integer NOT NULL,
    detail_id integer,
    name text
);


--
-- Name: module_platforms_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE module_platforms_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: module_platforms_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE module_platforms_id_seq OWNED BY module_platforms.id;


--
-- Name: module_refs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE module_refs (
    id integer NOT NULL,
    detail_id integer,
    name text
);


--
-- Name: module_refs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE module_refs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: module_refs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE module_refs_id_seq OWNED BY module_refs.id;


--
-- Name: module_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE module_runs (
    id integer NOT NULL,
    attempted_at timestamp without time zone,
    fail_detail text,
    fail_reason character varying,
    module_fullname text,
    port integer,
    proto character varying,
    session_id integer,
    status character varying,
    trackable_id integer,
    trackable_type character varying,
    user_id integer,
    username character varying,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: module_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE module_runs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: module_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE module_runs_id_seq OWNED BY module_runs.id;


--
-- Name: module_targets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE module_targets (
    id integer NOT NULL,
    detail_id integer,
    index integer,
    name text
);


--
-- Name: module_targets_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE module_targets_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: module_targets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE module_targets_id_seq OWNED BY module_targets.id;


--
-- Name: nexpose_consoles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE nexpose_consoles (
    id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    enabled boolean DEFAULT true,
    owner text,
    address text,
    port integer DEFAULT 3780,
    username text,
    password text,
    status text,
    version text,
    cert text,
    cached_sites bytea,
    name text
);


--
-- Name: nexpose_consoles_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE nexpose_consoles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: nexpose_consoles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE nexpose_consoles_id_seq OWNED BY nexpose_consoles.id;


--
-- Name: notes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE notes (
    id integer NOT NULL,
    created_at timestamp without time zone,
    ntype character varying(512),
    workspace_id integer DEFAULT 1 NOT NULL,
    service_id integer,
    host_id integer,
    updated_at timestamp without time zone,
    critical boolean,
    seen boolean,
    data text,
    vuln_id integer
);


--
-- Name: notes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE notes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: notes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE notes_id_seq OWNED BY notes.id;


--
-- Name: profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE profiles (
    id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    active boolean DEFAULT true,
    name text,
    owner text,
    settings bytea
);


--
-- Name: profiles_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE profiles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: profiles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE profiles_id_seq OWNED BY profiles.id;


--
-- Name: refs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE refs (
    id integer NOT NULL,
    ref_id integer,
    created_at timestamp without time zone,
    name character varying(512),
    updated_at timestamp without time zone
);


--
-- Name: refs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE refs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: refs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE refs_id_seq OWNED BY refs.id;


--
-- Name: report_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE report_templates (
    id integer NOT NULL,
    workspace_id integer DEFAULT 1 NOT NULL,
    created_by character varying,
    path character varying(1024),
    name text,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: report_templates_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE report_templates_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: report_templates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE report_templates_id_seq OWNED BY report_templates.id;


--
-- Name: reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE reports (
    id integer NOT NULL,
    workspace_id integer DEFAULT 1 NOT NULL,
    created_by character varying,
    rtype character varying,
    path character varying(1024),
    options text,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    downloaded_at timestamp without time zone,
    task_id integer,
    name character varying(63)
);


--
-- Name: reports_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE reports_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: reports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE reports_id_seq OWNED BY reports.id;


--
-- Name: routes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE routes (
    id integer NOT NULL,
    session_id integer,
    subnet character varying,
    netmask character varying
);


--
-- Name: routes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE routes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: routes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE routes_id_seq OWNED BY routes.id;


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE schema_migrations (
    version character varying NOT NULL
);


--
-- Name: services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE services (
    id integer NOT NULL,
    host_id integer,
    created_at timestamp without time zone,
    port integer NOT NULL,
    proto character varying(16) NOT NULL,
    state character varying,
    name character varying,
    updated_at timestamp without time zone,
    info text
);


--
-- Name: services_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE services_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: services_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE services_id_seq OWNED BY services.id;


--
-- Name: session_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE session_events (
    id integer NOT NULL,
    session_id integer,
    etype character varying,
    command bytea,
    output bytea,
    remote_path character varying,
    local_path character varying,
    created_at timestamp without time zone
);


--
-- Name: session_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE session_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: session_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE session_events_id_seq OWNED BY session_events.id;


--
-- Name: sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE sessions (
    id integer NOT NULL,
    host_id integer,
    stype character varying,
    via_exploit character varying,
    via_payload character varying,
    "desc" character varying,
    port integer,
    platform character varying,
    datastore text,
    opened_at timestamp without time zone NOT NULL,
    closed_at timestamp without time zone,
    close_reason character varying,
    local_id integer,
    last_seen timestamp without time zone,
    module_run_id integer
);


--
-- Name: sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE sessions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE sessions_id_seq OWNED BY sessions.id;


--
-- Name: tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE tags (
    id integer NOT NULL,
    user_id integer,
    name character varying(1024),
    "desc" text,
    report_summary boolean DEFAULT false NOT NULL,
    report_detail boolean DEFAULT false NOT NULL,
    critical boolean DEFAULT false NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: tags_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE tags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE tags_id_seq OWNED BY tags.id;


--
-- Name: task_creds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE task_creds (
    id integer NOT NULL,
    task_id integer NOT NULL,
    cred_id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: task_creds_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE task_creds_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: task_creds_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE task_creds_id_seq OWNED BY task_creds.id;


--
-- Name: task_hosts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE task_hosts (
    id integer NOT NULL,
    task_id integer NOT NULL,
    host_id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: task_hosts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE task_hosts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: task_hosts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE task_hosts_id_seq OWNED BY task_hosts.id;


--
-- Name: task_services; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE task_services (
    id integer NOT NULL,
    task_id integer NOT NULL,
    service_id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: task_services_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE task_services_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: task_services_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE task_services_id_seq OWNED BY task_services.id;


--
-- Name: task_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE task_sessions (
    id integer NOT NULL,
    task_id integer NOT NULL,
    session_id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: task_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE task_sessions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: task_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE task_sessions_id_seq OWNED BY task_sessions.id;


--
-- Name: tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE tasks (
    id integer NOT NULL,
    workspace_id integer DEFAULT 1 NOT NULL,
    created_by character varying,
    module character varying,
    completed_at timestamp without time zone,
    path character varying(1024),
    info character varying,
    description character varying,
    progress integer,
    options text,
    error text,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    result text,
    module_uuid character varying(8),
    settings bytea
);


--
-- Name: tasks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE tasks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tasks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE tasks_id_seq OWNED BY tasks.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE users (
    id integer NOT NULL,
    username character varying,
    crypted_password character varying,
    password_salt character varying,
    persistence_token character varying,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    fullname character varying,
    email character varying,
    phone character varying,
    company character varying,
    prefs character varying(524288),
    admin boolean DEFAULT true NOT NULL
);


--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE users_id_seq OWNED BY users.id;


--
-- Name: vuln_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE vuln_attempts (
    id integer NOT NULL,
    vuln_id integer,
    attempted_at timestamp without time zone,
    exploited boolean,
    fail_reason character varying,
    username character varying,
    module text,
    session_id integer,
    loot_id integer,
    fail_detail text
);


--
-- Name: vuln_attempts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE vuln_attempts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vuln_attempts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE vuln_attempts_id_seq OWNED BY vuln_attempts.id;


--
-- Name: vuln_details; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE vuln_details (
    id integer NOT NULL,
    vuln_id integer,
    cvss_score double precision,
    cvss_vector character varying,
    title character varying,
    description text,
    solution text,
    proof bytea,
    nx_console_id integer,
    nx_device_id integer,
    nx_vuln_id character varying,
    nx_severity double precision,
    nx_pci_severity double precision,
    nx_published timestamp without time zone,
    nx_added timestamp without time zone,
    nx_modified timestamp without time zone,
    nx_tags text,
    nx_vuln_status text,
    nx_proof_key text,
    src character varying,
    nx_scan_id integer,
    nx_vulnerable_since timestamp without time zone,
    nx_pci_compliance_status character varying
);


--
-- Name: vuln_details_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE vuln_details_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vuln_details_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE vuln_details_id_seq OWNED BY vuln_details.id;


--
-- Name: vulns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE vulns (
    id integer NOT NULL,
    host_id integer,
    service_id integer,
    created_at timestamp without time zone,
    name character varying,
    updated_at timestamp without time zone,
    info character varying(65536),
    exploited_at timestamp without time zone,
    vuln_detail_count integer DEFAULT 0,
    vuln_attempt_count integer DEFAULT 0,
    origin_id integer,
    origin_type character varying
);


--
-- Name: vulns_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE vulns_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vulns_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE vulns_id_seq OWNED BY vulns.id;


--
-- Name: vulns_refs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE vulns_refs (
    ref_id integer,
    vuln_id integer,
    id integer NOT NULL
);


--
-- Name: vulns_refs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE vulns_refs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vulns_refs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE vulns_refs_id_seq OWNED BY vulns_refs.id;


--
-- Name: web_forms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE web_forms (
    id integer NOT NULL,
    web_site_id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    path text,
    method character varying(1024),
    params text,
    query text
);


--
-- Name: web_forms_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE web_forms_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: web_forms_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE web_forms_id_seq OWNED BY web_forms.id;


--
-- Name: web_pages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE web_pages (
    id integer NOT NULL,
    web_site_id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    path text,
    query text,
    code integer NOT NULL,
    cookie text,
    auth text,
    ctype text,
    mtime timestamp without time zone,
    location text,
    headers text,
    body bytea,
    request bytea
);


--
-- Name: web_pages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE web_pages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: web_pages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE web_pages_id_seq OWNED BY web_pages.id;


--
-- Name: web_sites; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE web_sites (
    id integer NOT NULL,
    service_id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    vhost character varying(2048),
    comments text,
    options text
);


--
-- Name: web_sites_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE web_sites_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: web_sites_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE web_sites_id_seq OWNED BY web_sites.id;


--
-- Name: web_vulns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE web_vulns (
    id integer NOT NULL,
    web_site_id integer NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    path text NOT NULL,
    method character varying(1024) NOT NULL,
    params text,
    pname text,
    risk integer NOT NULL,
    name character varying(1024) NOT NULL,
    query text,
    category text NOT NULL,
    confidence integer NOT NULL,
    description text,
    blame text,
    request bytea,
    proof bytea NOT NULL,
    owner character varying,
    payload text
);


--
-- Name: web_vulns_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE web_vulns_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: web_vulns_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE web_vulns_id_seq OWNED BY web_vulns.id;


--
-- Name: wmap_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE wmap_requests (
    id integer NOT NULL,
    host character varying,
    address inet,
    port integer,
    ssl integer,
    meth character varying(32),
    path text,
    headers text,
    query text,
    body text,
    respcode character varying(16),
    resphead text,
    response text,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: wmap_requests_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE wmap_requests_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: wmap_requests_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE wmap_requests_id_seq OWNED BY wmap_requests.id;


--
-- Name: wmap_targets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE wmap_targets (
    id integer NOT NULL,
    host character varying,
    address inet,
    port integer,
    ssl integer,
    selected integer,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: wmap_targets_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE wmap_targets_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: wmap_targets_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE wmap_targets_id_seq OWNED BY wmap_targets.id;


--
-- Name: workspace_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE workspace_members (
    workspace_id integer NOT NULL,
    user_id integer NOT NULL
);


--
-- Name: workspaces; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE workspaces (
    id integer NOT NULL,
    name character varying,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    boundary character varying(4096),
    description character varying(4096),
    owner_id integer,
    limit_to_network boolean DEFAULT false NOT NULL,
    import_fingerprint boolean DEFAULT false
);


--
-- Name: workspaces_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE workspaces_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: workspaces_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE workspaces_id_seq OWNED BY workspaces.id;


--
-- Name: api_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY api_keys ALTER COLUMN id SET DEFAULT nextval('api_keys_id_seq'::regclass);


--
-- Name: automatic_exploitation_match_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY automatic_exploitation_match_results ALTER COLUMN id SET DEFAULT nextval('automatic_exploitation_match_results_id_seq'::regclass);


--
-- Name: automatic_exploitation_match_sets id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY automatic_exploitation_match_sets ALTER COLUMN id SET DEFAULT nextval('automatic_exploitation_match_sets_id_seq'::regclass);


--
-- Name: automatic_exploitation_matches id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY automatic_exploitation_matches ALTER COLUMN id SET DEFAULT nextval('automatic_exploitation_matches_id_seq'::regclass);


--
-- Name: automatic_exploitation_runs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY automatic_exploitation_runs ALTER COLUMN id SET DEFAULT nextval('automatic_exploitation_runs_id_seq'::regclass);


--
-- Name: clients id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY clients ALTER COLUMN id SET DEFAULT nextval('clients_id_seq'::regclass);


--
-- Name: creds id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY creds ALTER COLUMN id SET DEFAULT nextval('creds_id_seq'::regclass);


--
-- Name: events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY events ALTER COLUMN id SET DEFAULT nextval('events_id_seq'::regclass);


--
-- Name: exploit_attempts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY exploit_attempts ALTER COLUMN id SET DEFAULT nextval('exploit_attempts_id_seq'::regclass);


--
-- Name: exploited_hosts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY exploited_hosts ALTER COLUMN id SET DEFAULT nextval('exploited_hosts_id_seq'::regclass);


--
-- Name: host_details id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY host_details ALTER COLUMN id SET DEFAULT nextval('host_details_id_seq'::regclass);


--
-- Name: hosts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY hosts ALTER COLUMN id SET DEFAULT nextval('hosts_id_seq'::regclass);


--
-- Name: hosts_tags id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY hosts_tags ALTER COLUMN id SET DEFAULT nextval('hosts_tags_id_seq'::regclass);


--
-- Name: listeners id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY listeners ALTER COLUMN id SET DEFAULT nextval('listeners_id_seq'::regclass);


--
-- Name: loots id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY loots ALTER COLUMN id SET DEFAULT nextval('loots_id_seq'::regclass);


--
-- Name: macros id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY macros ALTER COLUMN id SET DEFAULT nextval('macros_id_seq'::regclass);


--
-- Name: metasploit_credential_cores id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_cores ALTER COLUMN id SET DEFAULT nextval('metasploit_credential_cores_id_seq'::regclass);


--
-- Name: metasploit_credential_logins id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_logins ALTER COLUMN id SET DEFAULT nextval('metasploit_credential_logins_id_seq'::regclass);


--
-- Name: metasploit_credential_origin_cracked_passwords id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_origin_cracked_passwords ALTER COLUMN id SET DEFAULT nextval('metasploit_credential_origin_cracked_passwords_id_seq'::regclass);


--
-- Name: metasploit_credential_origin_imports id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_origin_imports ALTER COLUMN id SET DEFAULT nextval('metasploit_credential_origin_imports_id_seq'::regclass);


--
-- Name: metasploit_credential_origin_manuals id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_origin_manuals ALTER COLUMN id SET DEFAULT nextval('metasploit_credential_origin_manuals_id_seq'::regclass);


--
-- Name: metasploit_credential_origin_services id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_origin_services ALTER COLUMN id SET DEFAULT nextval('metasploit_credential_origin_services_id_seq'::regclass);


--
-- Name: metasploit_credential_origin_sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_origin_sessions ALTER COLUMN id SET DEFAULT nextval('metasploit_credential_origin_sessions_id_seq'::regclass);


--
-- Name: metasploit_credential_privates id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_privates ALTER COLUMN id SET DEFAULT nextval('metasploit_credential_privates_id_seq'::regclass);


--
-- Name: metasploit_credential_publics id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_publics ALTER COLUMN id SET DEFAULT nextval('metasploit_credential_publics_id_seq'::regclass);


--
-- Name: metasploit_credential_realms id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_realms ALTER COLUMN id SET DEFAULT nextval('metasploit_credential_realms_id_seq'::regclass);


--
-- Name: mod_refs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY mod_refs ALTER COLUMN id SET DEFAULT nextval('mod_refs_id_seq'::regclass);


--
-- Name: module_actions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_actions ALTER COLUMN id SET DEFAULT nextval('module_actions_id_seq'::regclass);


--
-- Name: module_archs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_archs ALTER COLUMN id SET DEFAULT nextval('module_archs_id_seq'::regclass);


--
-- Name: module_authors id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_authors ALTER COLUMN id SET DEFAULT nextval('module_authors_id_seq'::regclass);


--
-- Name: module_details id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_details ALTER COLUMN id SET DEFAULT nextval('module_details_id_seq'::regclass);


--
-- Name: module_mixins id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_mixins ALTER COLUMN id SET DEFAULT nextval('module_mixins_id_seq'::regclass);


--
-- Name: module_platforms id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_platforms ALTER COLUMN id SET DEFAULT nextval('module_platforms_id_seq'::regclass);


--
-- Name: module_refs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_refs ALTER COLUMN id SET DEFAULT nextval('module_refs_id_seq'::regclass);


--
-- Name: module_runs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_runs ALTER COLUMN id SET DEFAULT nextval('module_runs_id_seq'::regclass);


--
-- Name: module_targets id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_targets ALTER COLUMN id SET DEFAULT nextval('module_targets_id_seq'::regclass);


--
-- Name: nexpose_consoles id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY nexpose_consoles ALTER COLUMN id SET DEFAULT nextval('nexpose_consoles_id_seq'::regclass);


--
-- Name: notes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY notes ALTER COLUMN id SET DEFAULT nextval('notes_id_seq'::regclass);


--
-- Name: profiles id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY profiles ALTER COLUMN id SET DEFAULT nextval('profiles_id_seq'::regclass);


--
-- Name: refs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY refs ALTER COLUMN id SET DEFAULT nextval('refs_id_seq'::regclass);


--
-- Name: report_templates id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY report_templates ALTER COLUMN id SET DEFAULT nextval('report_templates_id_seq'::regclass);


--
-- Name: reports id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY reports ALTER COLUMN id SET DEFAULT nextval('reports_id_seq'::regclass);


--
-- Name: routes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY routes ALTER COLUMN id SET DEFAULT nextval('routes_id_seq'::regclass);


--
-- Name: services id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY services ALTER COLUMN id SET DEFAULT nextval('services_id_seq'::regclass);


--
-- Name: session_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY session_events ALTER COLUMN id SET DEFAULT nextval('session_events_id_seq'::regclass);


--
-- Name: sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY sessions ALTER COLUMN id SET DEFAULT nextval('sessions_id_seq'::regclass);


--
-- Name: tags id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY tags ALTER COLUMN id SET DEFAULT nextval('tags_id_seq'::regclass);


--
-- Name: task_creds id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY task_creds ALTER COLUMN id SET DEFAULT nextval('task_creds_id_seq'::regclass);


--
-- Name: task_hosts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY task_hosts ALTER COLUMN id SET DEFAULT nextval('task_hosts_id_seq'::regclass);


--
-- Name: task_services id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY task_services ALTER COLUMN id SET DEFAULT nextval('task_services_id_seq'::regclass);


--
-- Name: task_sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY task_sessions ALTER COLUMN id SET DEFAULT nextval('task_sessions_id_seq'::regclass);


--
-- Name: tasks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY tasks ALTER COLUMN id SET DEFAULT nextval('tasks_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY users ALTER COLUMN id SET DEFAULT nextval('users_id_seq'::regclass);


--
-- Name: vuln_attempts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY vuln_attempts ALTER COLUMN id SET DEFAULT nextval('vuln_attempts_id_seq'::regclass);


--
-- Name: vuln_details id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY vuln_details ALTER COLUMN id SET DEFAULT nextval('vuln_details_id_seq'::regclass);


--
-- Name: vulns id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulns ALTER COLUMN id SET DEFAULT nextval('vulns_id_seq'::regclass);


--
-- Name: vulns_refs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulns_refs ALTER COLUMN id SET DEFAULT nextval('vulns_refs_id_seq'::regclass);


--
-- Name: web_forms id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY web_forms ALTER COLUMN id SET DEFAULT nextval('web_forms_id_seq'::regclass);


--
-- Name: web_pages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY web_pages ALTER COLUMN id SET DEFAULT nextval('web_pages_id_seq'::regclass);


--
-- Name: web_sites id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY web_sites ALTER COLUMN id SET DEFAULT nextval('web_sites_id_seq'::regclass);


--
-- Name: web_vulns id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY web_vulns ALTER COLUMN id SET DEFAULT nextval('web_vulns_id_seq'::regclass);


--
-- Name: wmap_requests id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY wmap_requests ALTER COLUMN id SET DEFAULT nextval('wmap_requests_id_seq'::regclass);


--
-- Name: wmap_targets id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY wmap_targets ALTER COLUMN id SET DEFAULT nextval('wmap_targets_id_seq'::regclass);


--
-- Name: workspaces id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY workspaces ALTER COLUMN id SET DEFAULT nextval('workspaces_id_seq'::regclass);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: automatic_exploitation_match_results automatic_exploitation_match_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY automatic_exploitation_match_results
    ADD CONSTRAINT automatic_exploitation_match_results_pkey PRIMARY KEY (id);


--
-- Name: automatic_exploitation_match_sets automatic_exploitation_match_sets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY automatic_exploitation_match_sets
    ADD CONSTRAINT automatic_exploitation_match_sets_pkey PRIMARY KEY (id);


--
-- Name: automatic_exploitation_matches automatic_exploitation_matches_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY automatic_exploitation_matches
    ADD CONSTRAINT automatic_exploitation_matches_pkey PRIMARY KEY (id);


--
-- Name: automatic_exploitation_runs automatic_exploitation_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY automatic_exploitation_runs
    ADD CONSTRAINT automatic_exploitation_runs_pkey PRIMARY KEY (id);


--
-- Name: clients clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY clients
    ADD CONSTRAINT clients_pkey PRIMARY KEY (id);


--
-- Name: creds creds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY creds
    ADD CONSTRAINT creds_pkey PRIMARY KEY (id);


--
-- Name: events events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY events
    ADD CONSTRAINT events_pkey PRIMARY KEY (id);


--
-- Name: exploit_attempts exploit_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY exploit_attempts
    ADD CONSTRAINT exploit_attempts_pkey PRIMARY KEY (id);


--
-- Name: exploited_hosts exploited_hosts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY exploited_hosts
    ADD CONSTRAINT exploited_hosts_pkey PRIMARY KEY (id);


--
-- Name: host_details host_details_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY host_details
    ADD CONSTRAINT host_details_pkey PRIMARY KEY (id);


--
-- Name: hosts hosts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY hosts
    ADD CONSTRAINT hosts_pkey PRIMARY KEY (id);


--
-- Name: hosts_tags hosts_tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY hosts_tags
    ADD CONSTRAINT hosts_tags_pkey PRIMARY KEY (id);


--
-- Name: listeners listeners_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY listeners
    ADD CONSTRAINT listeners_pkey PRIMARY KEY (id);


--
-- Name: loots loots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY loots
    ADD CONSTRAINT loots_pkey PRIMARY KEY (id);


--
-- Name: macros macros_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY macros
    ADD CONSTRAINT macros_pkey PRIMARY KEY (id);


--
-- Name: metasploit_credential_cores metasploit_credential_cores_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_cores
    ADD CONSTRAINT metasploit_credential_cores_pkey PRIMARY KEY (id);


--
-- Name: metasploit_credential_logins metasploit_credential_logins_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_logins
    ADD CONSTRAINT metasploit_credential_logins_pkey PRIMARY KEY (id);


--
-- Name: metasploit_credential_origin_cracked_passwords metasploit_credential_origin_cracked_passwords_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_origin_cracked_passwords
    ADD CONSTRAINT metasploit_credential_origin_cracked_passwords_pkey PRIMARY KEY (id);


--
-- Name: metasploit_credential_origin_imports metasploit_credential_origin_imports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_origin_imports
    ADD CONSTRAINT metasploit_credential_origin_imports_pkey PRIMARY KEY (id);


--
-- Name: metasploit_credential_origin_manuals metasploit_credential_origin_manuals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_origin_manuals
    ADD CONSTRAINT metasploit_credential_origin_manuals_pkey PRIMARY KEY (id);


--
-- Name: metasploit_credential_origin_services metasploit_credential_origin_services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_origin_services
    ADD CONSTRAINT metasploit_credential_origin_services_pkey PRIMARY KEY (id);


--
-- Name: metasploit_credential_origin_sessions metasploit_credential_origin_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_origin_sessions
    ADD CONSTRAINT metasploit_credential_origin_sessions_pkey PRIMARY KEY (id);


--
-- Name: metasploit_credential_privates metasploit_credential_privates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_privates
    ADD CONSTRAINT metasploit_credential_privates_pkey PRIMARY KEY (id);


--
-- Name: metasploit_credential_publics metasploit_credential_publics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_publics
    ADD CONSTRAINT metasploit_credential_publics_pkey PRIMARY KEY (id);


--
-- Name: metasploit_credential_realms metasploit_credential_realms_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY metasploit_credential_realms
    ADD CONSTRAINT metasploit_credential_realms_pkey PRIMARY KEY (id);


--
-- Name: mod_refs mod_refs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY mod_refs
    ADD CONSTRAINT mod_refs_pkey PRIMARY KEY (id);


--
-- Name: module_actions module_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_actions
    ADD CONSTRAINT module_actions_pkey PRIMARY KEY (id);


--
-- Name: module_archs module_archs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_archs
    ADD CONSTRAINT module_archs_pkey PRIMARY KEY (id);


--
-- Name: module_authors module_authors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_authors
    ADD CONSTRAINT module_authors_pkey PRIMARY KEY (id);


--
-- Name: module_details module_details_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_details
    ADD CONSTRAINT module_details_pkey PRIMARY KEY (id);


--
-- Name: module_mixins module_mixins_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_mixins
    ADD CONSTRAINT module_mixins_pkey PRIMARY KEY (id);


--
-- Name: module_platforms module_platforms_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_platforms
    ADD CONSTRAINT module_platforms_pkey PRIMARY KEY (id);


--
-- Name: module_refs module_refs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_refs
    ADD CONSTRAINT module_refs_pkey PRIMARY KEY (id);


--
-- Name: module_runs module_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_runs
    ADD CONSTRAINT module_runs_pkey PRIMARY KEY (id);


--
-- Name: module_targets module_targets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY module_targets
    ADD CONSTRAINT module_targets_pkey PRIMARY KEY (id);


--
-- Name: nexpose_consoles nexpose_consoles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY nexpose_consoles
    ADD CONSTRAINT nexpose_consoles_pkey PRIMARY KEY (id);


--
-- Name: notes notes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY notes
    ADD CONSTRAINT notes_pkey PRIMARY KEY (id);


--
-- Name: profiles profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY profiles
    ADD CONSTRAINT profiles_pkey PRIMARY KEY (id);


--
-- Name: refs refs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY refs
    ADD CONSTRAINT refs_pkey PRIMARY KEY (id);


--
-- Name: report_templates report_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY report_templates
    ADD CONSTRAINT report_templates_pkey PRIMARY KEY (id);


--
-- Name: reports reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY reports
    ADD CONSTRAINT reports_pkey PRIMARY KEY (id);


--
-- Name: routes routes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY routes
    ADD CONSTRAINT routes_pkey PRIMARY KEY (id);


--
-- Name: services services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY services
    ADD CONSTRAINT services_pkey PRIMARY KEY (id);


--
-- Name: session_events session_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY session_events
    ADD CONSTRAINT session_events_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: tags tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY tags
    ADD CONSTRAINT tags_pkey PRIMARY KEY (id);


--
-- Name: task_creds task_creds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY task_creds
    ADD CONSTRAINT task_creds_pkey PRIMARY KEY (id);


--
-- Name: task_hosts task_hosts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY task_hosts
    ADD CONSTRAINT task_hosts_pkey PRIMARY KEY (id);


--
-- Name: task_services task_services_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY task_services
    ADD CONSTRAINT task_services_pkey PRIMARY KEY (id);


--
-- Name: task_sessions task_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY task_sessions
    ADD CONSTRAINT task_sessions_pkey PRIMARY KEY (id);


--
-- Name: tasks tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY tasks
    ADD CONSTRAINT tasks_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: vuln_attempts vuln_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vuln_attempts
    ADD CONSTRAINT vuln_attempts_pkey PRIMARY KEY (id);


--
-- Name: vuln_details vuln_details_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vuln_details
    ADD CONSTRAINT vuln_details_pkey PRIMARY KEY (id);


--
-- Name: vulns vulns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulns
    ADD CONSTRAINT vulns_pkey PRIMARY KEY (id);


--
-- Name: vulns_refs vulns_refs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY vulns_refs
    ADD CONSTRAINT vulns_refs_pkey PRIMARY KEY (id);


--
-- Name: web_forms web_forms_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY web_forms
    ADD CONSTRAINT web_forms_pkey PRIMARY KEY (id);


--
-- Name: web_pages web_pages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY web_pages
    ADD CONSTRAINT web_pages_pkey PRIMARY KEY (id);


--
-- Name: web_sites web_sites_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY web_sites
    ADD CONSTRAINT web_sites_pkey PRIMARY KEY (id);


--
-- Name: web_vulns web_vulns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY web_vulns
    ADD CONSTRAINT web_vulns_pkey PRIMARY KEY (id);


--
-- Name: wmap_requests wmap_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY wmap_requests
    ADD CONSTRAINT wmap_requests_pkey PRIMARY KEY (id);


--
-- Name: wmap_targets wmap_targets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY wmap_targets
    ADD CONSTRAINT wmap_targets_pkey PRIMARY KEY (id);


--
-- Name: workspaces workspaces_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY workspaces
    ADD CONSTRAINT workspaces_pkey PRIMARY KEY (id);


--
-- Name: index_automatic_exploitation_match_results_on_match_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_automatic_exploitation_match_results_on_match_id ON automatic_exploitation_match_results USING btree (match_id);


--
-- Name: index_automatic_exploitation_match_results_on_run_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_automatic_exploitation_match_results_on_run_id ON automatic_exploitation_match_results USING btree (run_id);


--
-- Name: index_automatic_exploitation_match_sets_on_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_automatic_exploitation_match_sets_on_user_id ON automatic_exploitation_match_sets USING btree (user_id);


--
-- Name: index_automatic_exploitation_match_sets_on_workspace_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_automatic_exploitation_match_sets_on_workspace_id ON automatic_exploitation_match_sets USING btree (workspace_id);


--
-- Name: index_automatic_exploitation_matches_on_module_detail_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_automatic_exploitation_matches_on_module_detail_id ON automatic_exploitation_matches USING btree (module_detail_id);


--
-- Name: index_automatic_exploitation_matches_on_module_fullname; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_automatic_exploitation_matches_on_module_fullname ON automatic_exploitation_matches USING btree (module_fullname);


--
-- Name: index_automatic_exploitation_runs_on_match_set_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_automatic_exploitation_runs_on_match_set_id ON automatic_exploitation_runs USING btree (match_set_id);


--
-- Name: index_automatic_exploitation_runs_on_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_automatic_exploitation_runs_on_user_id ON automatic_exploitation_runs USING btree (user_id);


--
-- Name: index_automatic_exploitation_runs_on_workspace_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_automatic_exploitation_runs_on_workspace_id ON automatic_exploitation_runs USING btree (workspace_id);


--
-- Name: index_hosts_on_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_hosts_on_name ON hosts USING btree (name);


--
-- Name: index_hosts_on_os_flavor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_hosts_on_os_flavor ON hosts USING btree (os_flavor);


--
-- Name: index_hosts_on_os_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_hosts_on_os_name ON hosts USING btree (os_name);


--
-- Name: index_hosts_on_purpose; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_hosts_on_purpose ON hosts USING btree (purpose);


--
-- Name: index_hosts_on_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_hosts_on_state ON hosts USING btree (state);


--
-- Name: index_hosts_on_workspace_id_and_address; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_hosts_on_workspace_id_and_address ON hosts USING btree (workspace_id, address);


--
-- Name: index_loots_on_module_run_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_loots_on_module_run_id ON loots USING btree (module_run_id);


--
-- Name: index_metasploit_credential_cores_on_origin_type_and_origin_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_metasploit_credential_cores_on_origin_type_and_origin_id ON metasploit_credential_cores USING btree (origin_type, origin_id);


--
-- Name: index_metasploit_credential_cores_on_private_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_metasploit_credential_cores_on_private_id ON metasploit_credential_cores USING btree (private_id);


--
-- Name: index_metasploit_credential_cores_on_public_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_metasploit_credential_cores_on_public_id ON metasploit_credential_cores USING btree (public_id);


--
-- Name: index_metasploit_credential_cores_on_realm_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_metasploit_credential_cores_on_realm_id ON metasploit_credential_cores USING btree (realm_id);


--
-- Name: index_metasploit_credential_cores_on_workspace_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_metasploit_credential_cores_on_workspace_id ON metasploit_credential_cores USING btree (workspace_id);


--
-- Name: index_metasploit_credential_logins_on_core_id_and_service_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_metasploit_credential_logins_on_core_id_and_service_id ON metasploit_credential_logins USING btree (core_id, service_id);


--
-- Name: index_metasploit_credential_logins_on_service_id_and_core_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_metasploit_credential_logins_on_service_id_and_core_id ON metasploit_credential_logins USING btree (service_id, core_id);


--
-- Name: index_metasploit_credential_origin_imports_on_task_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_metasploit_credential_origin_imports_on_task_id ON metasploit_credential_origin_imports USING btree (task_id);


--
-- Name: index_metasploit_credential_origin_manuals_on_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_metasploit_credential_origin_manuals_on_user_id ON metasploit_credential_origin_manuals USING btree (user_id);


--
-- Name: index_metasploit_credential_privates_on_type_and_data; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_metasploit_credential_privates_on_type_and_data ON metasploit_credential_privates USING btree (type, data) WHERE (NOT ((type)::text = 'Metasploit::Credential::SSHKey'::text));


--
-- Name: index_metasploit_credential_privates_on_type_and_data_sshkey; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_metasploit_credential_privates_on_type_and_data_sshkey ON metasploit_credential_privates USING btree (type, decode(md5(data), 'hex'::text)) WHERE ((type)::text = 'Metasploit::Credential::SSHKey'::text);


--
-- Name: index_metasploit_credential_publics_on_username; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_metasploit_credential_publics_on_username ON metasploit_credential_publics USING btree (username);


--
-- Name: index_metasploit_credential_realms_on_key_and_value; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_metasploit_credential_realms_on_key_and_value ON metasploit_credential_realms USING btree (key, value);


--
-- Name: index_module_actions_on_detail_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_module_actions_on_detail_id ON module_actions USING btree (detail_id);


--
-- Name: index_module_archs_on_detail_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_module_archs_on_detail_id ON module_archs USING btree (detail_id);


--
-- Name: index_module_authors_on_detail_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_module_authors_on_detail_id ON module_authors USING btree (detail_id);


--
-- Name: index_module_details_on_description; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_module_details_on_description ON module_details USING btree (description);


--
-- Name: index_module_details_on_mtype; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_module_details_on_mtype ON module_details USING btree (mtype);


--
-- Name: index_module_details_on_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_module_details_on_name ON module_details USING btree (name);


--
-- Name: index_module_details_on_refname; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_module_details_on_refname ON module_details USING btree (refname);


--
-- Name: index_module_mixins_on_detail_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_module_mixins_on_detail_id ON module_mixins USING btree (detail_id);


--
-- Name: index_module_platforms_on_detail_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_module_platforms_on_detail_id ON module_platforms USING btree (detail_id);


--
-- Name: index_module_refs_on_detail_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_module_refs_on_detail_id ON module_refs USING btree (detail_id);


--
-- Name: index_module_refs_on_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_module_refs_on_name ON module_refs USING btree (name);


--
-- Name: index_module_runs_on_session_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_module_runs_on_session_id ON module_runs USING btree (session_id);


--
-- Name: index_module_runs_on_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_module_runs_on_user_id ON module_runs USING btree (user_id);


--
-- Name: index_module_targets_on_detail_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_module_targets_on_detail_id ON module_targets USING btree (detail_id);


--
-- Name: index_notes_on_ntype; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_notes_on_ntype ON notes USING btree (ntype);


--
-- Name: index_notes_on_vuln_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_notes_on_vuln_id ON notes USING btree (vuln_id);


--
-- Name: index_refs_on_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_refs_on_name ON refs USING btree (name);


--
-- Name: index_services_on_host_id_and_port_and_proto; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX index_services_on_host_id_and_port_and_proto ON services USING btree (host_id, port, proto);


--
-- Name: index_services_on_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_services_on_name ON services USING btree (name);


--
-- Name: index_services_on_port; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_services_on_port ON services USING btree (port);


--
-- Name: index_services_on_proto; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_services_on_proto ON services USING btree (proto);


--
-- Name: index_services_on_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_services_on_state ON services USING btree (state);


--
-- Name: index_sessions_on_module_run_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_sessions_on_module_run_id ON sessions USING btree (module_run_id);


--
-- Name: index_vulns_on_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_vulns_on_name ON vulns USING btree (name);


--
-- Name: index_vulns_on_origin_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_vulns_on_origin_id ON vulns USING btree (origin_id);


--
-- Name: index_web_forms_on_path; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_web_forms_on_path ON web_forms USING btree (path);


--
-- Name: index_web_pages_on_path; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_web_pages_on_path ON web_pages USING btree (path);


--
-- Name: index_web_pages_on_query; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_web_pages_on_query ON web_pages USING btree (query);


--
-- Name: index_web_sites_on_comments; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_web_sites_on_comments ON web_sites USING btree (comments);


--
-- Name: index_web_sites_on_options; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_web_sites_on_options ON web_sites USING btree (options);


--
-- Name: index_web_sites_on_vhost; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_web_sites_on_vhost ON web_sites USING btree (vhost);


--
-- Name: index_web_vulns_on_method; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_web_vulns_on_method ON web_vulns USING btree (method);


--
-- Name: index_web_vulns_on_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_web_vulns_on_name ON web_vulns USING btree (name);


--
-- Name: index_web_vulns_on_path; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX index_web_vulns_on_path ON web_vulns USING btree (path);


--
-- Name: originating_credential_cores; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX originating_credential_cores ON metasploit_credential_origin_cracked_passwords USING btree (metasploit_credential_core_id);


--
-- Name: unique_complete_metasploit_credential_cores; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX unique_complete_metasploit_credential_cores ON metasploit_credential_cores USING btree (workspace_id, realm_id, public_id, private_id) WHERE ((realm_id IS NOT NULL) AND (public_id IS NOT NULL) AND (private_id IS NOT NULL));


--
-- Name: unique_metasploit_credential_origin_services; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX unique_metasploit_credential_origin_services ON metasploit_credential_origin_services USING btree (service_id, module_full_name);


--
-- Name: unique_metasploit_credential_origin_sessions; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX unique_metasploit_credential_origin_sessions ON metasploit_credential_origin_sessions USING btree (session_id, post_reference_name);


--
-- Name: unique_private_metasploit_credential_cores; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX unique_private_metasploit_credential_cores ON metasploit_credential_cores USING btree (workspace_id, private_id) WHERE ((realm_id IS NULL) AND (public_id IS NULL) AND (private_id IS NOT NULL));


--
-- Name: unique_privateless_metasploit_credential_cores; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX unique_privateless_metasploit_credential_cores ON metasploit_credential_cores USING btree (workspace_id, realm_id, public_id) WHERE ((realm_id IS NOT NULL) AND (public_id IS NOT NULL) AND (private_id IS NULL));


--
-- Name: unique_public_metasploit_credential_cores; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX unique_public_metasploit_credential_cores ON metasploit_credential_cores USING btree (workspace_id, public_id) WHERE ((realm_id IS NULL) AND (public_id IS NOT NULL) AND (private_id IS NULL));


--
-- Name: unique_publicless_metasploit_credential_cores; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX unique_publicless_metasploit_credential_cores ON metasploit_credential_cores USING btree (workspace_id, realm_id, private_id) WHERE ((realm_id IS NOT NULL) AND (public_id IS NULL) AND (private_id IS NOT NULL));


--
-- Name: unique_realmless_metasploit_credential_cores; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX unique_realmless_metasploit_credential_cores ON metasploit_credential_cores USING btree (workspace_id, public_id, private_id) WHERE ((realm_id IS NULL) AND (public_id IS NOT NULL) AND (private_id IS NOT NULL));


--
-- Name: unique_schema_migrations; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX unique_schema_migrations ON schema_migrations USING btree (version);


--
-- PostgreSQL database dump complete
--

SET search_path TO "$user", public;

INSERT INTO schema_migrations (version) VALUES ('0');

INSERT INTO schema_migrations (version) VALUES ('1');

INSERT INTO schema_migrations (version) VALUES ('10');

INSERT INTO schema_migrations (version) VALUES ('11');

INSERT INTO schema_migrations (version) VALUES ('12');

INSERT INTO schema_migrations (version) VALUES ('13');

INSERT INTO schema_migrations (version) VALUES ('14');

INSERT INTO schema_migrations (version) VALUES ('15');

INSERT INTO schema_migrations (version) VALUES ('16');

INSERT INTO schema_migrations (version) VALUES ('17');

INSERT INTO schema_migrations (version) VALUES ('18');

INSERT INTO schema_migrations (version) VALUES ('19');

INSERT INTO schema_migrations (version) VALUES ('2');

INSERT INTO schema_migrations (version) VALUES ('20');

INSERT INTO schema_migrations (version) VALUES ('20100819123300');

INSERT INTO schema_migrations (version) VALUES ('20100824151500');

INSERT INTO schema_migrations (version) VALUES ('20100908001428');

INSERT INTO schema_migrations (version) VALUES ('20100911122000');

INSERT INTO schema_migrations (version) VALUES ('20100916151530');

INSERT INTO schema_migrations (version) VALUES ('20100916175000');

INSERT INTO schema_migrations (version) VALUES ('20100920012100');

INSERT INTO schema_migrations (version) VALUES ('20100926214000');

INSERT INTO schema_migrations (version) VALUES ('20101001000000');

INSERT INTO schema_migrations (version) VALUES ('20101002000000');

INSERT INTO schema_migrations (version) VALUES ('20101007000000');

INSERT INTO schema_migrations (version) VALUES ('20101008111800');

INSERT INTO schema_migrations (version) VALUES ('20101009023300');

INSERT INTO schema_migrations (version) VALUES ('20101104135100');

INSERT INTO schema_migrations (version) VALUES ('20101203000000');

INSERT INTO schema_migrations (version) VALUES ('20101203000001');

INSERT INTO schema_migrations (version) VALUES ('20101206212033');

INSERT INTO schema_migrations (version) VALUES ('20110112154300');

INSERT INTO schema_migrations (version) VALUES ('20110204112800');

INSERT INTO schema_migrations (version) VALUES ('20110317144932');

INSERT INTO schema_migrations (version) VALUES ('20110414180600');

INSERT INTO schema_migrations (version) VALUES ('20110415175705');

INSERT INTO schema_migrations (version) VALUES ('20110422000000');

INSERT INTO schema_migrations (version) VALUES ('20110425095900');

INSERT INTO schema_migrations (version) VALUES ('20110513143900');

INSERT INTO schema_migrations (version) VALUES ('20110517160800');

INSERT INTO schema_migrations (version) VALUES ('20110527000000');

INSERT INTO schema_migrations (version) VALUES ('20110527000001');

INSERT INTO schema_migrations (version) VALUES ('20110606000001');

INSERT INTO schema_migrations (version) VALUES ('20110622000000');

INSERT INTO schema_migrations (version) VALUES ('20110624000001');

INSERT INTO schema_migrations (version) VALUES ('20110625000001');

INSERT INTO schema_migrations (version) VALUES ('20110630000001');

INSERT INTO schema_migrations (version) VALUES ('20110630000002');

INSERT INTO schema_migrations (version) VALUES ('20110717000001');

INSERT INTO schema_migrations (version) VALUES ('20110727163801');

INSERT INTO schema_migrations (version) VALUES ('20110730000001');

INSERT INTO schema_migrations (version) VALUES ('20110812000001');

INSERT INTO schema_migrations (version) VALUES ('20110922000000');

INSERT INTO schema_migrations (version) VALUES ('20110928101300');

INSERT INTO schema_migrations (version) VALUES ('20111011110000');

INSERT INTO schema_migrations (version) VALUES ('20111203000000');

INSERT INTO schema_migrations (version) VALUES ('20111204000000');

INSERT INTO schema_migrations (version) VALUES ('20111210000000');

INSERT INTO schema_migrations (version) VALUES ('20120126110000');

INSERT INTO schema_migrations (version) VALUES ('20120411173220');

INSERT INTO schema_migrations (version) VALUES ('20120601152442');

INSERT INTO schema_migrations (version) VALUES ('20120625000000');

INSERT INTO schema_migrations (version) VALUES ('20120625000001');

INSERT INTO schema_migrations (version) VALUES ('20120625000002');

INSERT INTO schema_migrations (version) VALUES ('20120625000003');

INSERT INTO schema_migrations (version) VALUES ('20120625000004');

INSERT INTO schema_migrations (version) VALUES ('20120625000005');

INSERT INTO schema_migrations (version) VALUES ('20120625000006');

INSERT INTO schema_migrations (version) VALUES ('20120625000007');

INSERT INTO schema_migrations (version) VALUES ('20120625000008');

INSERT INTO schema_migrations (version) VALUES ('20120718202805');

INSERT INTO schema_migrations (version) VALUES ('20130228214900');

INSERT INTO schema_migrations (version) VALUES ('20130412154159');

INSERT INTO schema_migrations (version) VALUES ('20130412171844');

INSERT INTO schema_migrations (version) VALUES ('20130412173121');

INSERT INTO schema_migrations (version) VALUES ('20130412173640');

INSERT INTO schema_migrations (version) VALUES ('20130412174254');

INSERT INTO schema_migrations (version) VALUES ('20130412174719');

INSERT INTO schema_migrations (version) VALUES ('20130412175040');

INSERT INTO schema_migrations (version) VALUES ('20130423211152');

INSERT INTO schema_migrations (version) VALUES ('20130430151353');

INSERT INTO schema_migrations (version) VALUES ('20130430162145');

INSERT INTO schema_migrations (version) VALUES ('20130510021637');

INSERT INTO schema_migrations (version) VALUES ('20130515164311');

INSERT INTO schema_migrations (version) VALUES ('20130515172727');

INSERT INTO schema_migrations (version) VALUES ('20130516204810');

INSERT INTO schema_migrations (version) VALUES ('20130522001343');

INSERT INTO schema_migrations (version) VALUES ('20130522032517');

INSERT INTO schema_migrations (version) VALUES ('20130522041110');

INSERT INTO schema_migrations (version) VALUES ('20130525015035');

INSERT INTO schema_migrations (version) VALUES ('20130525212420');

INSERT INTO schema_migrations (version) VALUES ('20130531144949');

INSERT INTO schema_migrations (version) VALUES ('20130604145732');

INSERT INTO schema_migrations (version) VALUES ('20130717150737');

INSERT INTO schema_migrations (version) VALUES ('20131002004641');

INSERT INTO schema_migrations (version) VALUES ('20131002164449');

INSERT INTO schema_migrations (version) VALUES ('20131008213344');

INSERT INTO schema_migrations (version) VALUES ('20131011184338');

INSERT INTO schema_migrations (version) VALUES ('20131017150735');

INSERT INTO schema_migrations (version) VALUES ('20131021185657');

INSERT INTO schema_migrations (version) VALUES ('20140331173835');

INSERT INTO schema_migrations (version) VALUES ('20140407212345');

INSERT INTO schema_migrations (version) VALUES ('20140410132401');

INSERT INTO schema_migrations (version) VALUES ('20140410161611');

INSERT INTO schema_migrations (version) VALUES ('20140410191213');

INSERT INTO schema_migrations (version) VALUES ('20140410205410');

INSERT INTO schema_migrations (version) VALUES ('20140411142102');

INSERT INTO schema_migrations (version) VALUES ('20140411205325');

INSERT INTO schema_migrations (version) VALUES ('20140414192550');

INSERT INTO schema_migrations (version) VALUES ('20140417140933');

INSERT INTO schema_migrations (version) VALUES ('20140520140817');

INSERT INTO schema_migrations (version) VALUES ('20140603163708');

INSERT INTO schema_migrations (version) VALUES ('20140605173747');

INSERT INTO schema_migrations (version) VALUES ('20140702184622');

INSERT INTO schema_migrations (version) VALUES ('20140703144541');

INSERT INTO schema_migrations (version) VALUES ('20140722174919');

INSERT INTO schema_migrations (version) VALUES ('20140728191933');

INSERT INTO schema_migrations (version) VALUES ('20140801150537');

INSERT INTO schema_migrations (version) VALUES ('20140905031549');

INSERT INTO schema_migrations (version) VALUES ('20140922170030');

INSERT INTO schema_migrations (version) VALUES ('20150106201450');

INSERT INTO schema_migrations (version) VALUES ('20150112203945');

INSERT INTO schema_migrations (version) VALUES ('20150205192745');

INSERT INTO schema_migrations (version) VALUES ('20150209195939');

INSERT INTO schema_migrations (version) VALUES ('20150212214222');

INSERT INTO schema_migrations (version) VALUES ('20150219173821');

INSERT INTO schema_migrations (version) VALUES ('20150219215039');

INSERT INTO schema_migrations (version) VALUES ('20150226151459');

INSERT INTO schema_migrations (version) VALUES ('20150312155312');

INSERT INTO schema_migrations (version) VALUES ('20150317145455');

INSERT INTO schema_migrations (version) VALUES ('20150326183742');

INSERT INTO schema_migrations (version) VALUES ('20150421211719');

INSERT INTO schema_migrations (version) VALUES ('20150514182921');

INSERT INTO schema_migrations (version) VALUES ('20160415153312');

INSERT INTO schema_migrations (version) VALUES ('20161004165612');

INSERT INTO schema_migrations (version) VALUES ('20161107153145');

INSERT INTO schema_migrations (version) VALUES ('20161107203710');

INSERT INTO schema_migrations (version) VALUES ('20161227212223');

INSERT INTO schema_migrations (version) VALUES ('21');

INSERT INTO schema_migrations (version) VALUES ('22');

INSERT INTO schema_migrations (version) VALUES ('23');

INSERT INTO schema_migrations (version) VALUES ('24');

INSERT INTO schema_migrations (version) VALUES ('25');

INSERT INTO schema_migrations (version) VALUES ('26');

INSERT INTO schema_migrations (version) VALUES ('3');

INSERT INTO schema_migrations (version) VALUES ('4');

INSERT INTO schema_migrations (version) VALUES ('5');

INSERT INTO schema_migrations (version) VALUES ('6');

INSERT INTO schema_migrations (version) VALUES ('7');

INSERT INTO schema_migrations (version) VALUES ('8');

INSERT INTO schema_migrations (version) VALUES ('9');

