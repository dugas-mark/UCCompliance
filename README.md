# getHCACompliance

Configuration Compliance Checking Utility for HCA Unified Communcations environment.

## Deployment

### Dependencies
The dependencies for running the application are included in the "requirements.txt" file.
This utility is written to read/write to SalesForce tables with information on UC equipment in the HCA environment.  The tables are:
```
    UC_Divisions__c
    UC_Clusters__c
    UC_Sites__c
```

```
Cisco API's used:
    From AXLAPI:
        getCCMVersion:  getCUCMVer
         listPhone:  getRegisteredDeviceCnt
        doAuthenticateUser:  checkStandardPwd
        getLdapSystem:  getCUCMLdap
        listLdapDirectory:  getCUCMLdap
        getLdapFilter:  getCUCMLdap
        getServiceParameter:  getCUCMClusterID
        
    From RisPort70
        selectCmDeviceExt:  getRegisteredDeviceCnt, mrCheck

    From PAWS
         MaintenceService
            getBackupProgress:  getBackupStatus

    From Control Center Services
        soapGetServiceStatus:  getCUCMPubInfo

    From Perfmon Service
        perfmonListInstance:  getCUCMOvaInfo
        perfmonCollectCounterData:  getCUCMOvaInfo

 SalesForce API's used:
    simple_salesforce
         Salesforce:  updateSalesForce
         SalesforceLogin:  updateSalesForce
         SFType:  updateSalesForce

```

### Application
The utility 

