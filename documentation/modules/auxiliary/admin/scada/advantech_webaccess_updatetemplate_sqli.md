## Description

This module exploits a SQL injection vulnerability in Advantech WebAccess. The flaw can be found
in the ```updateSubmit_Click``` function of the ```updateTemplate``` class, which is normally used for
updating a *.xlsx template.

The ```updateSubmit_Click``` function calls ```getTemplateIdByName``` from the ```DAO``` class
(Data Access Object), which is actually where the SQL injection bug is:

```
// This line is from Page_Load
// As you can see, template is user-controlled
this.templateName = this.Request.QueryString["template"];

... skipped ...

protected void updateSubmit_Click(object sender, EventArgs e)
{
  DAO dao = new DAO(this.mdbPath, this.logPath);
  int templateIdByName = dao.getTemplateIdByName(this.templateName);

... skipped ...

```

The ```getTemplateIdByName``` function will execute a SQL statement with a user-supplied ```template```
name, like so:

```
OleDbDataReader oleDbDataReader = new OleDbCommand("SELECT TemplateId FROM rRptTemplate WHERE TemplateName = '" + templateName + "'", this.conn).ExecuteReader();
```

Since there is no input validation for the ```template``` parameter, this can be exploited to
inject additional SQL statements, and have data stolen. This module specifically steals
credentials from existing project users stored in config/bwCfg.mdb.

Although authentication is required, by default Advantech WebAccess uses a blank password for the
built-in ```admin``` account, which allows the SQL injection vulnerability easier to exploit.

## Vulnerable Application

AdvanTech WebAccess 8.1 was specifically tested during development.

To download this software for testing:

http://advcloudfiles.advantech.com/web/Download/webaccess/8.1/AdvantechWebAccessUSANode8.1_20151230.exe

Before testing, you should make sure that WebAccess has:

* At least one project.
* At least one node
* At least one project user.

All the above can be configured from the management console.


## Usage

Due to the nature of the vulnerability, before you use this module, you should come up with a list
of usernames to try. The Metasploit Framework has its own collection of username lists in the
data/wordlists directory, and we will use one one of them in the following demonstration.

The basic usage of the module would look something like this:

1. Start msfconsole
2. Do ```use auxiliary/admin/scada/advantech_webaccess_updatetemplate_sqli```
3. Do ```set USER_FILE /msf/data/wordlists/unix_users.txt```
4. Do ```set RHOST [IP]```
5. Do ```run```


## Options

**WEBACCESSUSER**

The username to log into Advantech WebAccess. By default, the web application uses ```admin``` as
the default username, which is a built-in account that does not get deleted. It is also possible to
log in as a different project user.

**WEBACCESSPASS**

The password to log into Advantech WebAccess. By default, the built-in username ```admin``` does
not require a password, therefore this option is optional by default.

## Demo

![webaccess_demo](https://cloud.githubusercontent.com/assets/1170914/22172751/34cff104-df75-11e6-9243-efd97f3762ac.gif)
