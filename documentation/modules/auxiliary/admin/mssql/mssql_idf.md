## Description

This (Interesting Data Finder) module will connect to a remote MSSQL server using a given set of credentials and search for rows and columns with "interesting" names. This information can help you fine-tune further attacks against the database.

### Setup

Install MSSQL server on a windows machine.

Set up an example database and table with interesting columns:

```tsql
USE [master];

-- Drop and create a new example database if it exists
GO
IF DB_ID (N'example_database') IS NOT NULL
    DROP DATABASE [example_database];
GO
CREATE DATABASE [example_database];
GO

-- Use the new database

USE [example_database];
GO

-- Create an interesting table
CREATE TABLE [example_table] (
    ExampleId INT NOT NULL PRIMARY KEY,
    Username NVARCHAR(255),
    Email NVARCHAR(255),
    Password NVARCHAR(255),
    BankCreditCard NVARCHAR(255)
);
GO

-- Create interesting data
INSERT INTO [example_table] (ExampleId, Username, Email, Password, BankCreditCard)
VALUES
    (1, 'username-1', 'email-1', 'password-1', 'bank-credit-card-1'),
    (2, 'username-2', 'email-2', 'password-2', 'bank-credit-card-2');
GO
```

## Verification Steps

1. Do: ```use auxiliary/admin/mssql/mssql_idf```
2. Do: ```set RHOSTS [IP]```
3. Do: ```set THREADS [number of threads]```
4. Do: ```run```

## Scenarios

```
msf > use auxiliary/admin/mssql/mssql_idf
msf auxiliary(mssql_idf) > set NAMES username|password
NAMES => username|password
msf auxiliary(mssql_idf) > set PASSWORD password1
PASSWORD => password1
msf auxiliary(mssql_idf) > set RHOST 192.168.1.195
RHOST => 192.168.1.195
msf auxiliary(mssql_idf) > run


Database Schema Table          Column                Data Type Row Count 

======== ====== ============== ===================== ========= ========= ======== ====== ============== ===================== ========= ========= 

msdb     dbo    sysmail_server username              nvarchar  0

msdb     dbo    backupmediaset is_password_protected bit       0

msdb     dbo    backupset      is_password_protected bit       0

logins   dbo    userpass       username              varchar   3

logins   dbo    userpass       password              varchar   3


[*] Auxiliary module execution completed
msf auxiliary(mssql_idf) >
```
