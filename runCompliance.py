# getHcaCompliance.py 
#
# Mark Dugas, February, 2022
#
# Ad hoc script to check configuration compliance of HCA Unified Communications Managers
# The script will loop over the set of known HCA CUCM Publishers provided in dictionary CUCM_PUBS_D
#
# Execution requirement:
#	Current working directory must contain:
#		1)  A copy of the cucm_env.py file with relevant information
#		2)  The XML API subset libraries cucmXmlLibnn_n.py where nn_n is the CUCM version number, must be in current working directory.
#			**NOTE** - CUCM version 14.0 is not supported at this time - Cisco discovered a bug in the SNMP API
#
# Cisco API's used:
#	From AXLAPI:
#		getCCMVersion:  getCUCMVer
# 		listPhone:  getRegisteredDeviceCnt
#		doAuthenticateUser:  checkStandardPwd
#		getLdapSystem:  getCUCMLdap
#		listLdapDirectory:  getCUCMLdap
#		getLdapFilter:  getCUCMLdap
#		getServiceParameter:  getCUCMClusterID
#		
#	From RisPort70
#		selectCmDeviceExt:  getRegisteredDeviceCnt, mrCheck
#
#	From PAWS
# 		MaintenceService
#			getBackupProgress:  getBackupStatus
#
#	From Control Center Services
#		soapGetServiceStatus:  getCUCMPubInfo
#
#	From Perfmon Service
#		perfmonListInstance:  getCUCMOvaInfo
#		perfmonCollectCounterData:  getCUCMOvaInfo
#
# SalesForce API's used:
#	simple_salesforce
# 		Salesforce:  updateSalesForce
# 		SalesforceLogin:  updateSalesForce
# 		SFType:  updateSalesForce
#
# __main__ method:
# 	The __main__ method will:
#		1)  Set up logging
#		2)  Loop over all CUCM Publisher IP addresses in list CUCM_PUBS_D
#		3)  Within the publisher loop:
# 			a: the CUCM cluster version will be determined for appropriate WSDL selection
#				i: version is returned from locally defined method getCUCMVer as a 4 character string in format 'xx.x' for WSDL selection
# 			b: Multi-threading of most function calls via concurrent.features ThreadPoolExecutor
#			c: All function calls return a dictionary of the form:  {'Sales Force Variable':'Compliance Value'}
#		4)  After all list items in CUCM_PUBS_D have been processed, the log file is closed and the script ends
#

# Get required variables/methods from local libraries
import os
from cucm_env import SfInfo, WSDL_URL, Creds, CUCM_PUBS_D
from getHcaCompliance import *
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

if __name__ == "__main__":
	# CUCM_PUBS_D = {'10.160.44.132':'FWD-1'}
	# Supress warnings
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

	# Create a timestamped log file compliancCheck.log for this run
	logger = logSetup('complianceCheck')

	for CUCM_IP in CUCM_PUBS_D:
		with ThreadPoolExecutor(max_workers=20) as executor:
			logger.info(f'Checking PUB:  {CUCM_IP} {CUCM_PUBS_D[CUCM_IP]}')
			print(f'Checking PUB:  {CUCM_IP} {CUCM_PUBS_D[CUCM_IP]}')

			cucmFullVer = getCUCMVer(Creds['username'], Creds['passwd'], CUCM_IP, WSDL_URL, logger)
			WSDL_URL = f'{os.getcwd()}\\WSDL_{cucmFullVer["Cluster_Version__c"][0:4]}\\'

			executor._thread_name_prefix = 'ucmClusterID'
			ucmClusterID = executor.submit(getCUCMClusterID, Creds['username'], Creds['passwd'], CUCM_IP, WSDL_URL, logger)

			executor._thread_name_prefix = 'passwordStatus'
			passwordStatus = executor.submit(checkStandardPwd, Creds['standardOsUserName'], Creds['standardCcmOsPwd'], 
											Creds['standardCcmAdminUserName'], Creds['standardCcmAdminPwd'],
											WSDL_URL, CUCM_IP, Creds['username'], Creds['passwd'], logger)
			
			for fut in as_completed([passwordStatus]):
				print('===> Future outcome passwordStatus finished')

			executor._thread_name_prefix = 'cucmLdap'
			cucmLdap = executor.submit(getCUCMLdap, Creds['username'], Creds['passwd'], CUCM_IP, WSDL_URL, logger)

			executor._thread_name_prefix = 'ovaSize'
			ovaSize = executor.submit(getCUCMOvaInfo, Creds['username'], Creds['passwd'], CUCM_IP, logger)

			executor._thread_name_prefix = 'cucmPub'
			cucmPub = executor.submit(getCUCMPubInfo, Creds['username'], Creds['passwd'], CUCM_IP, logger)

			executor._thread_name_prefix = 'mrStatus'
			mrStatus = executor.submit(mrCheck, Creds['username'], Creds['passwd'], CUCM_IP, logger)

			#cmgLoad = getCUCMCmgLoad(Creds['username'], Creds['passwd'], CUCM_IP, WSDL_URL)

			if passwordStatus.result()['OS_Pwd_Status__c'] != 'False':
				backupStatus = getBackupStatus(Creds['standardOsUserName'], Creds['standardCcmOsPwd'], CUCM_IP, logger)
			else:
				backupStatus = {'Daily_Backup_Status__c':False, 'Last_Backup_Date__c':None}

			executor._thread_name_prefix = 'regDeviceCnt'
			regDeviceCnt = executor.submit(getRegisteredDeviceCnt, Creds['username'], Creds['passwd'], CUCM_IP, WSDL_URL, logger)

			for fut in as_completed([ucmClusterID, cucmLdap, ovaSize, cucmPub, mrStatus, regDeviceCnt]):
				pass

			# Combine all results into one dictionary
			SfDict = combineDict(logger, cucmFullVer, ucmClusterID.result(), passwordStatus.result(), 
								regDeviceCnt.result(), cucmLdap.result(), ovaSize.result(), 
								cucmPub.result(), mrStatus.result(), backupStatus) # removed cmgLoad temporarily
			
			# Update compliance information for this cluster.  
			updateSalesForce(SfInfo, SfDict, logger)

			# Reset WSDL back to 11.5 for next getCCMVersion
			WSDL_URL = f'{os.getcwd()}\\WSDL_11.5\\'
	
	print('\nDone')
