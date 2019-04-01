## Introduction

This module can be used to aid the generation of an organizational chart based on information
contained in Active Directory. The module itself uses ADSI to retrieve key information from AD
(manager, title, description etc) fields and then present it in a CSV file in the form:

```
cn,description,title,phone,department,division,e-mail,company,reports_to
```

The reports_to field is the only one which is generated; everything else is taken directly from AD.
The 'manager' field contains the DN of the manager assigned to that user, and this module simply
uses a regular expression to obtain the CN field of the manager.

This can then be imported into tools like [Microsoft Visio](https://products.office.com/en-us/visio/flowchart-software)
(using the organizational chart wizard) and it will construct a visual org chart from the
information there. Although visio supports the ability to generate Org charts if it is on a domain
joined machine, but there does not seem to be a way of doing this remotely (e.g. during a
red teaming exercise).

This should not be confused with security groups and AD managed groups; this is purely an
internal organizational hierarchy representation but could be very useful for situational awareness
or in order to construct a more plausible or targeted internal phishing exercise.

# Options

Option             | Value
-------------------| ---
ACTIVE_USERS_ONLY  | This will restrict the search for users to those whose accounts are Active. This would have the effect of excluding disabled accounts (e.g. employees who have resigned).
FILTER             | Any additional LDAP filtering that is required when searching for users.
WITH_MANAGERS_ONLY | If this is TRUE, the module will only include users who have a manger set (internally, this is implemented by adding (manager=*) to the ADSI query filter). This could be useful if not everyone has a manager set, but could mean that the top executive is not included either.
STORE_LOOT         | Store the results in a CSV file in loot. You'll almost certainly want this set to TRUE.

# Demo

For the purposes of this contrived example, the module has been configured to generate the CSV
reporting information for everyone with 'IT' somewhere in their common name.

```
msf post(make_csv_orgchart) > show options

Module options (post/windows/gather/make_csv_orgchart):

   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   ACTIVE_USERS_ONLY   true             yes       Only include active users (i.e. not disabled ones)
   DOMAIN                               no        The domain to query or distinguished name (e.g. DC=test,DC=com)
   FILTER              cn=*IT*          no        Additional LDAP filter to use when searching for users
   MAX_SEARCH          500              yes       Maximum values to retrieve, 0 for all.
   SESSION             2                yes       The session to run this module on.
   STORE_LOOT          true             yes       Store the organisational chart information in CSV format in loot
   WITH_MANAGERS_ONLY  false            no        Only users with managers

msf post(make_csv_orgchart) > run

Users & Managers
================

 cn                                description                title                                phone  department  division  e-mail                     company  reports_to
 --                                -----------                -----                                -----  ----------  --------  ------                     -------  ----------
 IT Manager                                                   Deputy GOAT IT Director                                           it.manager@goat.stu                 IT Director
 IT Director                                                  Director of Goat IT                                               it.director@goat.stu                
 IT Leader: Badger                                            Team Leader of Blue Team Operations                               it.leader.badger@goat.stu           IT Manager
 IT Leader: Otter                                             Team Leader: Offensive Operations                                 it.leader.otter@goat.stu            IT Manager
 Oswold Otter (IT Team)                                       Consultant                                                        oswold.otter@goat.stu               IT Leader: Otter
 Bertie Badger (IT Security Team)  Default pass is badger123  IT Security Team Deputy                                           bertie.badger@goat.stu              IT Leader: Badger

[*] CSV Organisational Chart Information saved to: /usr/home/s/stuart/.msf4/loot/20151221175733_stufusdev_192.0.2.140_ad.orgchart_189769.txt
[*] Post module execution completed
```

The contents of the CSV file are shown below:

```
$ cat /usr/home/s/stuart/.msf4/loot/20151221175733_stufusdev_192.0.2.140_ad.orgchart_189769.txt
cn,description,title,phone,department,division,e-mail,company,reports_to
"IT Manager","","Deputy GOAT IT Director","","","","it.manager@goat.stu","","IT Director"
"IT Director","","Director of Goat IT","","","","it.director@goat.stu","",""
"IT Leader: Badger","","Team Leader of Blue Team Operations","","","","it.leader.badger@goat.stu","","IT Manager"
"IT Leader: Otter","","Team Leader: Offensive Operations","","","","it.leader.otter@goat.stu","","IT Manager"
"Oswold Otter (IT Team)","","Consultant","","","","oswold.otter@goat.stu","","IT Leader: Otter"
"Bertie Badger (IT Security Team)","Default pass is badger123","IT Security Team Deputy","","","","bertie.badger@goat.stu","","IT Leader: Badger"
```

When this was imported into Visio with default options set, it produced the following organisational chart:

![screenshot_orgchart](https://cloud.githubusercontent.com/assets/12296344/11937572/f5906320-a80c-11e5-8faa-6439872df362.png)
