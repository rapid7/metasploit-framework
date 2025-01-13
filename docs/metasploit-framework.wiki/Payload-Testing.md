Payloads for Metasploit Framework can now be tested when opening pull requests. This is handled by GitHub actions within 
our CI, this workflow will build the payloads using the appropriate repositories and branches. It will then run our 
acceptance tests against those changes. This requires adding GitHub labels for each corresponding payload repository. 
The labels will contain the `payload-testing` prefix, each supporting testing for an external repository:
 - `payload-testing-branch` ([https://github.com/rapid7/metasploit-payloads/](https://github.com/rapid7/metasploit-payloads/))
 - `payload-testing-mettle-branch` ([https://github.com/rapid7/mettle/](https://github.com/rapid7/mettle/))

**_Note_**:

The long term aim is supporting workflow dispatches for this job, but that is currently not working as expected. So as a
work-around we will need to edit the workflow locally. Once the testing has been completed ensure the following locally 
changes are reverted before merging.

Once the appropriate repository label is added, you will need to edit the GitHub workflow to point at the specific 
repository and branch you want to test. Below I will outline some changes that are required to make this work, update 
the following lines like so:

1. Point at your forked repository - [line to update](https://github.com/rapid7/metasploit-framework/blob/2355ab546d02bfee99183083b12c6953836c12a1/.github/workflows/shared_meterpreter_acceptance.yml#L188):
```yaml
repository: foo-r7/metasploit-framework
```

2. Point at your forked repository branch - [line to update](https://github.com/rapid7/metasploit-framework/blob/2355ab546d02bfee99183083b12c6953836c12a1/.github/workflows/shared_meterpreter_acceptance.yml#L190):
```yaml
ref: fixes-all-the-bugs
```

3. Point at your forked repository that contains the payload changes you'd like to test - [line to update](https://github.com/rapid7/metasploit-framework/blob/2355ab546d02bfee99183083b12c6953836c12a1/.github/workflows/shared_meterpreter_acceptance.yml#L249)
```yaml
repository: foo-r7/metasploit-payloads
```

4. Point at your forked repository branch that contains the payload changes you'd like to test - [line to update](https://github.com/rapid7/metasploit-framework/blob/2355ab546d02bfee99183083b12c6953836c12a1/.github/workflows/shared_meterpreter_acceptance.yml#L251):
```yaml
ref: fixes-all-the-payload-bugs
```

Steps 3 and 4 outline the steps required when steps testing metasploit-payloads. The same steps apply for Mettle, the 
following lines would need updated:
 - Point at your forked repository that contain the payload changes you'd like to test - [line](https://github.com/rapid7/metasploit-framework/blob/2355ab546d02bfee99183083b12c6953836c12a1/.github/workflows/shared_meterpreter_acceptance.yml#L155).
 - Point at your forked repository branch that contains the payload changes you'd like to test - [line](https://github.com/rapid7/metasploit-framework/blob/2355ab546d02bfee99183083b12c6953836c12a1/.github/workflows/shared_meterpreter_acceptance.yml#L157).
