## Description

  This module scans a JBoss instance for a few vulnerabilities.

## Vulnerable Software

  The JBoss Enterprise Application Platform (or JBoss EAP) is a
  subscription-based/open-source Java EE-based application
  server runtime platform used for building, deploying, and
  hosting highly-transactional Java applications and services

  This module has been successfully tested on:

  * Apache-Coyote/1.1 ( Powered by Servlet 2.4; JBoss-4.2.0.GA (build: SVNTag=JBoss_4_2_0_GA date=200705111440)/Tomcat-5.5 )

## Verification Steps

  1. Do: ```use auxiliary/scanner/http/jboss_vulnscan```
  2. Do: ```set RHOSTS [IP]```
  3. Do: ```run```
