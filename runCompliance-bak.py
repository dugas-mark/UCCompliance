
import os
from cucm_env import *
from getHcaCompliance import *
import urllib3
import concurrent.futures

#from getRegisteredDeviceCnt import getRegisteredDeviceCnt

# with concurrent.futures.ThreadPoolExecutor() as executor:
#	executor.map(func, arg_list)
# CUCM_PUBS_D = {'10.54.44.134':'COR-1'}

#logSetup('complianceCheck')

if __name__ == "__main__":
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

	# CUCM_PUBS_D = {'10.160.108.134':'MTD-2'}
	# CUCM_PUBS_D = {'10.54.44.134':'COR-1'}

	for CUCM_IP in CUCM_PUBS_D:
		print('\nChecking PUB:  ', CUCM_IP, ' ', CUCM_PUBS_D[CUCM_IP])

		cucmFullVer = getCUCMVer(username, passwd, CUCM_IP, WSDL_URL)
		WSDL_URL = f'{os.getcwd()}\\WSDL_{cucmFullVer["Cluster_Version__c"][0:4]}\\'
		ucmClusterID = getCUCMClusterID(username, passwd, CUCM_IP, WSDL_URL)

		passwordStatus = checkStandardPwd(standardOsUserName, standardCcmOsPwd, 
										standardCcmAdminUserName, standardCcmAdminPwd,
										WSDL_URL, CUCM_IP, username, passwd)

		regDeviceCnt = getRegisteredDeviceCnt(username, passwd, CUCM_IP, WSDL_URL)

		cucmLdap = getCUCMLdap(username, passwd, CUCM_IP, WSDL_URL)

		ovaSize = getCUCMOvaInfo(username, passwd, CUCM_IP)

		cucmPub = getCUCMPubInfo(username, passwd, CUCM_IP)

		mrStatus = mrCheck(username, passwd, CUCM_IP)

		#cmgLoad = getCUCMCmgLoad(username, passwd, CUCM_IP, WSDL_URL)

		if passwordStatus['OS_Pwd_Status__c'] != 'False':
			backupStatus = getBackupStatus(standardOsUserName, standardCcmOsPwd, CUCM_IP)
		else:
			backupStatus = {'Daily_Backup_Status__c':False, 'Last_Backup_Date__c':None}

		SfDict = combineDict(cucmFullVer, ucmClusterID, passwordStatus, regDeviceCnt, cucmLdap, 
					ovaSize, cucmPub, mrStatus, backupStatus) # removed cmgLoad temporarily

		updateSalesForce(SfInfo, SfDict)

		# Reset WSDL back to 11.5 for next getCCMVersion
		WSDL_URL = f'{os.getcwd()}\\WSDL_11.5\\'
	
	print('\nDone')
