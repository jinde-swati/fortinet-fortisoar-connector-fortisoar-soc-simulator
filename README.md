# FortiSOAR SOC Simulator

The FortiSOAR SOC Simulator connector is used to create various scenarios. To configure this connector, open the FortiSOAR SOC Simulator Connector and in its "Configuration > Page" enter the following values for the configuration parameters  

- **Configuration Name**: Provide a name for this configuration and you can optionally mark this configuration as the “Default Configuration”. 
- **Import Scenarios**: Select this checkbox to import various scenarios. 
- **Load Threat Intelligence**: Whenever records are recreated for a scenario, they include known malicious indicators, such as IP addresses, file hash, etc. Selecting this checkbox randomly assigns the malicious indicators to records every time a record is created. Therefore, the records get created with new indicators each time.  

Once you have configured the FortiSOAR SOC Simulator connector, sample scenarios get created in Help > Scenario and now, you are all set to start using the content pack and creating demo records. 

### Contributing Scenario

First you will have to fork git repo https://github.com/fortinet-fortisoar/connector-fortisoar-soc-simulator. Here you will create a folder under 'scenarios' folder. The folder that you will create will contain two files
> **scenario_record.json**
   This file is scenario record
   
> **scenarion_configuration.json**
   This file is configuration export for a scenario

Lets discuss process in brief
- ##### Design
   - Design your scenario of ForiSOAR instance. Here you will create demo records , module , system view changes along with required playbooks. Apart from this , we need to create a 'Scenario Record'. This record will be launch point for scenario. Please check 'Scenario Record' section to see how to a create a Scenario Record.
- ##### Exporting Scenario
   - You can export secenario by selecting scneario record and execute playbook  - *Export  Scenario*
- ##### Exporting Scenario Configuration
   - You can export required configuration for a scenario using 'Configuration Export' option listed under 'Application Editor'
      - Here you export required module schema along with system view template, playbook collection , connector , users / team ,etc 

#### Creating Scenario Record
There are two ways to create a scenario record
- Record which refer playbook to create a scenario demo record
- Record which has demo record JSON playload. This method also allows user to add a placeholder for some values which can be replaced dynamically 

##### Scenario record referring playbook for creation of demo record 
While creating scenario add following in Steps section under 'Source' tab . Replace values at appropriate location 
<p>
{
  "Steps": [
    {
      "name": "<<Name of Scenario>>",
      "type": "executePlaybook",  << -- this tells we want to create demo record invoking a  playbook and  not alert record JSON
      "playbookIRI": "/api/3/workflows/<<GUID>>",  << -- IRI of playbook  
      "preCreateMessage": "<<Message you want to display before creation of demo record>>",
      "postCreateMessage": "<<Message you want to display after creation of demo record>>",
      "waitTimeforNextStep": "<<time in seconds to delay next step>>"
    }
  ]
}
</p>

>Complete Example
<p>
{
  "Steps": [
    {
      "name": "Concurrent Successful Authentications",
      "type": "executePlaybook",
      "playbookIRI": "/api/3/workflows/37603f90-ab2c-42a0-b183-50e92fdd2fd1",
      "preCreateMessage": "Creating demo record for Concurrent Successful Authentications",
      "postCreateMessage": "",
      "waitTimeforNextStep": "5"
    }
  ]
}
</p>
Note : Here we cannot set placeholder for a value to replaced dynamically while creation of demo record 

##### Scenario record referring alert playload

While creating scenario add following in Steps section under 'Source' tab . Replace values at appropriate location 
<p>
 {
  "Steps": [
    {
      "name": "<<Name of Scenario>>",
      "type": "createAlert",    << -- this tells we want to create demo record using alert record JSON and not playbook
      "alertFields": {
        <<<Alert Record JSON>>>
      },
      "preCreateMessage": "<<Message you want to display before creation of demo record>>",
      "postCreateMessage": "none",
      "waitTimeforNextStep": "<<time in seconds to delay next step>>"
    }
  ]
}
</p>
   
> Complete Example
   
<p>
{
  "Steps": [
    {
      "name": "Repeated Login Failures",
      "type": "createAlert",
      "alertFields": {
        "name": "Repeated Login Failures on 192.168.60.172",
        "type": "Brute Force Attempts",
        "state": "/api/3/picklists/a1bac09b-1441-45aa-ad1b-c88744e48e72",
        "source": "Syslog",
        "status": "Open",
        "severity": "low",
        "sourceIp": "{TR_MALICIOUS_IP}",
        "sourceType": "linux_secure",
        "sourcedata": "{\"host\":\"marketing.server.1\",\"rhost\":\"43.225.46.25\",\"pid\":\"5654\",\"_confstr\":\"source::/var/log/secure|host::ip-10-1-3-106|linux_secure\",\"date_zone\":\"local\",\"_eventtype_color\":\"\",\"_indextime\":\"1500279602\",\"euid\":\"0\",\"timeendpos\":\"16\",\"date_hour\":\"8\",\"source\":\"/var/log/secure\",\"process\":\"sshd\",\"date_wday\":\"monday\",\"_serial\":\"8\",\"_kv\":\"1\",\"punct\":\"__::_----_[]:_(:):__;_=_=_=_=_=_=...__=\",\"_sourcetype\":\"linux_secure\",\"_raw\":\"Jul 17 08:20:02 192.168.60.172 sshd[5654]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=43.225.46.25 user=root\",\"_si\":[\"10.1.3.32\",\"main\"],\"securonix_server\":\"10.1.3.32\",\"sourcetype\":\"linux_secure\",\"date_month\":\"july\",\"index\":\"main\",\"timestartpos\":\"0\",\"eventtype\":\"\",\"user\":\"root\",\"date_mday\":\"17\",\"linecount\":\"\",\"tty\":\"ssh\",\"event_id\":\"3F3CBAA2-CB55-4976-95EA-3627677F1EE3@@main@@00f9a277c2dce41ac744d522c35f8ccb\",\"uid\":\"0\",\"_time\":\"1500279602\",\"date_minute\":\"20\",\"date_year\":\"2017\",\"date_second\":\"2\"}",
        "description": "<p>Suspicious Login Failures on asset marketing.server.1 from 43.225.46.25&nbsp;</p>",
        "targetAsset": "marketing.server.1",
        "destinationIp": "192.168.60.172",
        "killChainPhase": "Reconnaissance",
        "destinationPort": "443"
      },
      "preCreateMessage": "Create Repeated Login Failure Alert",
      "postCreateMessage": "none",
      "waitTimeforNextStep": "5"
    }
  ]
}
</p>
Here "sourceIp": "{TR_MALICIOUS_IP}"   << this is an example set a placeholder where you want to change value of , here, sourceIP dynamically when demo record is created

Refer for more details about content pack: https://fusecommunity.fortinet.com/viewdocument/incident-response-content-pack?CommunityKey=9f1420e8-e3c6-4535-8cae-3fa714da66d8&tab=librarydocuments
