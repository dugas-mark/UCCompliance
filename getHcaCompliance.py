
from simple_salesforce import Salesforce, SalesforceLogin, SFType
import logging
from paramiko.ssh_exception import AuthenticationException
from requests import Session
from requests.auth import HTTPBasicAuth
from zeep import Client, Settings
from zeep.exceptions import Fault
from zeep.transports import Transport
from zeep.cache import SqliteCache
import paramiko
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

from cucm_env import CUCM_PUBS_D

def logSetup(filename):

	# Set up logging for results
	logging.Formatter.converter = time.gmtime
	logger = logging.getLogger(__name__)
	logger.setLevel(logging.INFO)
	formatter = logging.Formatter(
		fmt='%(asctime)s.%(msecs)03dZ - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%dT%H:%M:%S')
	# Create date stamped log file
	logFileName = f'{filename}{time.strftime("%Y-%m-%dT%H.%M",time.localtime())}.log'
	file_handler = logging.FileHandler(logFileName, mode='a')
	file_handler.setLevel(logging.INFO)
	file_handler.setFormatter(formatter)
	logger.addHandler(file_handler)

	return logger

def getRegisteredDeviceCnt(username, passwd, CUCM_IP, WSDL_URL, logger):

	# phoneCount dictionary will return results of device counts
	phoneCount = 	{'Phones_Registered__c':0,
					'Phones_Unregistered__c':0,
					'CTI_Registered__c':0,
					'CTI_Unregistered__c':0,
					'Analog_Phones__c':0
					}
	# groupCount will hold a list of all phone devices in this cluster
	groupCount = list()
	# grp1k will hold a list of lists, each sub-list will be a list of 1000 phone devices with sub-lists required to hold all phone devices
	grp1k = list()

	# Set up SOAP environment
	session = Session()
	session.auth = HTTPBasicAuth(username, passwd)
	session.verify = False
	transport = Transport(session=session, cache=SqliteCache(), timeout=60)
	settings = Settings(strict=False, xml_huge_tree=True)

	AXL_client = Client(WSDL_URL+'AXLAPI.wsdl',
						settings=settings, transport=transport)
	AXL_service = AXL_client.create_service('{http://www.cisco.com/AXLAPIService/}AXLAPIBinding',
											f'https://{CUCM_IP}:8443/axl/')
	# Call Cisco API list.Phone
	phone_list = AXL_service.listPhone(searchCriteria={'name' : '%'},
									   returnedTags={'name' : '', 'model' : ''})
	cti_list = AXL_service.listCtiRoutePoint(searchCriteria={'name' : '%'},
									   returnedTags={'name' : '', 'model' : ''})
	ctiCount = len(cti_list['return']['ctiRoutePoint'])
	# Create a list of phone deivces from return object phone_list from API call to listPhone
	phoneCount['Analog_Phones__c'] = len([phone['name'] for phone in phone_list['return']['phone'] if phone['model'] == 'Analog Phone'])
	groupCount = [phone['name'] for phone in phone_list['return']['phone'] 
				if (phone['model'] != 'Analog Phone') and (phone['model'] != 'CTI Route Point')]
	totalCount = len(groupCount)

	# limit is a lambda function that will iterate through 1000 phone devices at a time
	limit = lambda phones, n=1000: [phones[i:i + n] for i in range(0, len(phones), n)]

	# Create list of 1000 device lists
	grp1k = limit(groupCount)

	# Free up memory consumed by groupCount
	del groupCount

	# Set up RISService70 SOAP environment to get registration status
	RIS_client = Client(
		f'https://{CUCM_IP}:8443/realtimeservice2/services/RISService70?wsdl', transport=transport)
	RIS_service = RIS_client.create_service('{http://schemas.cisco.com/ast/soap}RisBinding',
											f'https://{CUCM_IP}:8443/realtimeservice2/services/RISService70')

	# Launch threads for API's to gather phone, cti registration status
	with ThreadPoolExecutor(max_workers=20) as devices_exe:
		try:
			risCall1 = list()
			for grpBy1000 in grp1k:

				selectionCriteria = checkRegistration(grpBy1000, 'Phone', 'Registered')
				devices_exe._thread_name_prefix = 'R-phones'
				risCall1.append(devices_exe.submit(RIS_service.selectCmDeviceExt,
					CmSelectionCriteria=selectionCriteria, StateInfo=''))

			for fut in as_completed(risCall1):
				phoneCount['Phones_Registered__c'] += fut.result().SelectCmDeviceResult.TotalDevicesFound

		except Exception as e:
			logger.error(f'getRegisteredDeviceCnt exception:  {e}')

		ctiItemList = [cti['name'] for cti in cti_list['return']['ctiRoutePoint']]

		selectionCriteria = checkRegistration(ctiItemList, 'Cti', 'Registered', model='73')

		risCall2 = RIS_service.selectCmDeviceExt(CmSelectionCriteria=selectionCriteria, StateInfo='')

		phoneCount['Phones_Unregistered__c'] = totalCount - phoneCount['Phones_Registered__c']
		phoneCount['CTI_Registered__c'] = risCall2.SelectCmDeviceResult.TotalDevicesFound
		phoneCount['CTI_Unregistered__c'] = ctiCount - phoneCount['CTI_Registered__c']

	# Return dictionary phoneCount with registered/unregistered counts of phones and cti
	return phoneCount

def checkRegistration(group, devType, regType, model='255'):
	CmSelectionCriteria = {
						"MaxReturnedDevices": "1000",
						"DeviceClass": devType,
						"Model": model,
						"Status": regType,
						#"NodeName": None,
						"SelectBy": "Name",
						"SelectItems": {
										"item": {"Item": ""}
										},
						"Protocol": "Any",
						"DownloadStatus": "Any"
						}
						
	# For devType = Phone and model = 255, pass the list of phone names to SelectItems.
	if model == '255' or model == '73':
		CmSelectionCriteria['SelectItems']['item']['Item'] = ",".join(group)

	return CmSelectionCriteria

def mrCheck(username, passwd, cucm_ip, logger):

#	Compliance script mrglCheck
#	michael hagans, DOF9318
#	8/6/2020
#
#   Verified no media resources are unregistered

	session = Session()
	session.auth = HTTPBasicAuth(username, passwd)
	session.verify = False
	transport = Transport(session=session)
	items = {'item': [{'Item': '*'}]}
	# Parameters to conduct search

	client = Client(
		f'https://{cucm_ip}:8443/realtimeservice2/services/RISService70?wsdl', transport=transport)
	criteria_type = client.get_type('ns0:CmSelectionCriteria')
	criteria = criteria_type(MaxReturnedDevices=1000, DeviceClass='MediaResources', Model=255, Status='UnRegistered',
							SelectBy='Name', Protocol='Any', DownloadStatus='Any', SelectItems=items)

	service = client.create_service('{http://schemas.cisco.com/ast/soap}RisBinding',
									f'https://{cucm_ip}:8443/realtimeservice2/services/RISService70')

	resp = service.selectCmDevice(CmSelectionCriteria=criteria, StateInfo='')
	if resp['SelectCmDeviceResult']['TotalDevicesFound'] != 0:
		return {'MR_Status__c': False}
	else:
		return {'MR_Status__c':True}

def getBackupStatus(username, passwd, cucm_ip, logger, timeout=60):

	session = Session()
	session.verify = False
	session.auth = HTTPBasicAuth(username, passwd)
	transport = Transport(session=session, timeout=timeout,
						  operation_timeout=timeout)
	settings = Settings(strict=False, xml_huge_tree=True)
	client = Client(
		f'https://{cucm_ip}:8443/platform-services/services/MaintenanceService?wsdl', transport=transport, settings=settings)
	service = client.create_service('{http://services.api.platform.vos.cisco.com}MaintenanceServiceSoap12Binding',
									f'https://{cucm_ip}:8443/platform-services/services/MaintenanceService.MaintenanceServiceHttpsSoap12Endpoint')

	result = service.getBackupProgress()
	if result.backupProgressResult['tarFile'] != None:
		d = re.search('\d\d\d\d-\d\d-\d\d',result.backupProgressResult['tarFile'])
		dateBkup = d.group()
	if result.backupProgressResult['status'].__contains__('SUCCESS'):
		return {'Daily_Backup_Status__c':True, 'Last_Backup_Date__c':dateBkup}
	else:
		return {'Daily_Backup_Status__c':False, 'Last_Backup_Date__c':None}

def checkStandardPwd(standardOsUserName, standardCcmOsPwd, 
					standardCcmAdminUserName,standardCcmAdminPwd, 
					wsdl_url, cucm_ip, username, passwd, logger):

	# Check CCMADmin OS password via CLI
	standardOsPwd = False
	standardGuiPwd = False
	ssh_client = paramiko.SSHClient()
	ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		ssh_client.connect(hostname=cucm_ip, username= standardOsUserName, password=standardCcmOsPwd, timeout=60)
		standardOsPwd = True
	except AuthenticationException as e:
		logger.error(f'Checking standard OS pwd auth failed:  {e}')
		standardOsPwd = False
	except Exception as e:
		logger.error(f'Checking standard OS pwd other exception  {e}')
		standardOsPwd = False
	ssh_client.close()

	# standardGuiPwd = requests.get(f'https://{cucm_ip}/ccmadmin/j_security_check', verify=False, auth=HTTPBasicAuth('CCMAdmin',standardCcmAdminPwd))
	session = Session()
	session.verify = False
	session.auth = HTTPBasicAuth(username, passwd)
	transport = Transport(session=session, timeout=60)
	settings = Settings(strict=False, xml_huge_tree=True)
	client = Client(wsdl_url+'AXLAPI.wsdl',
					settings=settings, transport=transport)
	service = client.create_service("{http://www.cisco.com/AXLAPIService/}AXLAPIBinding",
									 f'https://{cucm_ip}:8443/axl/')
	try:
		standardGuiPwd = bool(service.doAuthenticateUser(userid= standardCcmAdminUserName, 
										password=standardCcmAdminPwd)['return']['userAuthenticated'] == 'true')
		print('\n')						
	except Exception as e:
		# if doAuthenticateUser fails due to "unknown result occurred" mark as password failed
		logger.error(f'doAuthenticateUser exception:  {e}')
		standardGuiPwd = False

	return {'OS_Pwd_Status__c':str(standardOsPwd), 'GUI_Pwd_Status__c':str(standardGuiPwd)}

def getCUCMVer(username, passwd, cucm_ip, wsdl_url, logger):

	sess = Session()
	sess.verify = False
	sess.auth = HTTPBasicAuth(username, passwd)
	trans = Transport(session=sess, timeout=60)
	sett = Settings(strict=False, xml_huge_tree=True)

	clnt = Client(wsdl_url+'AXLAPI.wsdl',
					settings=sett, transport=trans)
	serv = clnt.create_service('{http://www.cisco.com/AXLAPIService/}AXLAPIBinding',
									f'https://{cucm_ip}:8443/axl/')
	try:
		response = serv.getCCMVersion()
	except Exception as e:
		logger.error(f'Issue in getCUCMVer:  {e}')
	return {'Cluster_Version__c' : response['return']['componentVersion']['version']}

def getCUCMPubInfo(username, passwd, cucm_ip, logger):

	session = Session()
	session.verify = False
	session.auth = HTTPBasicAuth(username, passwd)
	transport = Transport(session=session, timeout=60)
	settings = Settings(strict=False, xml_huge_tree=True)
	client = Client(f'https://{cucm_ip}:8443/controlcenterservice2/services/ControlCenterServices?wsdl',
					settings=settings, transport=transport)
	service = client.create_service('{http://schemas.cisco.com/ast/soap}ControlCenterServicesBinding',
									f'https://{cucm_ip}:8443/controlcenterservice2/services/ControlCenterServices')
	# method assumes that server URL is that of publisher; returns ServiceName='Cisco CallManager', ServiceStatus='whatever'
	statusControlCenter = service.soapGetServiceStatus(
		ServiceStatus='Cisco CallManager')
	try:
		if statusControlCenter['ServiceInfoList']['item'][0]['ServiceStatus'] == 'Started':
			return {'CM_Service_on_Pub__c':True}
		else:
			return {'CM_Service_on_Pub__c':False}
	except Exception as e:
		logger.error(f'Issue in getCUCMPubInfo:  {e}')

def getCUCMLdap(username, passwd, cucm_ip, wsdl_url, logger):

	session = Session()
	session.verify = False
	session.auth = HTTPBasicAuth(username, passwd)
	transport = Transport(session=session, timeout=60)
	settings = Settings(strict=False, xml_huge_tree=True,
						xsd_ignore_sequence_order=True)
	# ldAccessGrpName = []
	client = Client(wsdl_url+'AXLAPI.wsdl',
					settings=settings, transport=transport)
	service = client.create_service("{http://www.cisco.com/AXLAPIService/}AXLAPIBinding",
									f'https://{cucm_ip}:8443/axl/')
	
	# Check that LDAP is enabled

	if service.getLdapSystem()['return']['ldapSystem']['syncEnabled'] == 'false':
		# LDAP is not enabled on this CUCM, end LDAP check
		return {'LDAP_Status__c':False}

	# LDAP is enabled; check for standard admin access in at least one LDAP Directory
	# Search for conditions:
	#       LDAP User Search Base = 'DC=hca,DC=corpad,DC=net' AND
	#       LDAP Custom Filter for Users contains 'UCE' and 'CDE'
	# If true, LDAP check passes

	# Find all LDAP Directories configured for this cluster.

	nameLdapDirectory = service.listLdapDirectory(
		searchCriteria={'name': '%'}, returnedTags={'name': '', 'userSearchBase':''})
	if nameLdapDirectory['return'] == None:
		# LDAP was set to "on" but there are no LDAP directories configured, end LDAP check
		return {'LDAP_Status__c':False}
	
	for n in nameLdapDirectory['return']['ldapDirectory']:
		directoryFilter = service.getLdapDirectory(name = n.name,
										returnedTags = {'ldapFilter':''})
		if directoryFilter['return']['ldapDirectory']['ldapFilter']['_value_1'] == None:
			break
		ldapFilters = service.getLdapFilter(name=directoryFilter['return']['ldapDirectory']['ldapFilter']['_value_1'],
											returnedTags = {'name':'','filter':''})

		if (('UCE' in ldapFilters['return']['ldapFilter']['filter']) \
				or ('CDE' in ldapFilters['return']['ldapFilter']['filter'])) \
				and n.userSearchBase == 'DC=hca,DC=corpad,DC=net':
			return {'LDAP_Status__c':True}
		else:
			pass

	return {'LDAP_Status__c':False}

def getCUCMClusterID(username, passwd, cucm_ip, wsdl_url, logger):
	import re

	session = Session()
	session.verify = False
	session.auth = HTTPBasicAuth(username, passwd)
	transport = Transport(session=session, timeout=60)
	settings = Settings(strict=False, xml_huge_tree=True)

	client = Client(wsdl_url+'AXLAPI.wsdl',
					settings=settings, transport=transport)
	service = client.create_service("{http://www.cisco.com/AXLAPIService/}AXLAPIBinding",
									f'https://{cucm_ip}:8443/axl/')
	response = service.getServiceParameter(
		processNodeName='EnterpriseWideData', name='ClusterID', service='Enterprise Wide')

	clusterIDName = response['return']['serviceParameter']['value']

	# If non-standard Cluster-ID found on CUCM, set SalesForce Cluster-ID to correct value for reporting purposes
	if re.match('[A-Z][A-Z][A-Z]-[1-9]',clusterIDName) != None:
		return {'Cluster_ID__c':CUCM_PUBS_D[cucm_ip], 'Cluster_ID_Status__c' : True}
	else:
		return {'Cluster_ID__c':CUCM_PUBS_D[cucm_ip], 'Cluster_ID_Status__c' : False}

def getCUCMCmgLoad(username, passwd, cucm_ip, wsdl_url, logger):

	session = Session()
	session.verify = False
	session.auth = HTTPBasicAuth(username, passwd)
	transport = Transport(session=session, timeout=60)
	settings = Settings(strict=False, xml_huge_tree=True)

	client = Client(wsdl_url+'AXLAPI.wsdl',
					settings=settings, transport=transport)
	service = client.create_service('{http://www.cisco.com/AXLAPIService/}AXLAPIBinding',
									f'https://{cucm_ip}:8443/axl/')

	deviceQuery = service.executeSQLQuery(sql="""SELECT cmg.name AS CMG_Group, COUNT(d.name) AS IP_Phones 
					FROM device AS d 
					INNER JOIN devicepool AS dp ON d.fkDevicePool=dp.pkid 
					INNER JOIN callmanagergroup AS cmg ON dp.fkcallmanagergroup=cmg.pkid 
					INNER JOIN typemodel AS tm ON tm.enum=d.tkmodel 
					WHERE (tm.name != 'Analog Phone' AND tm.name != 'Conference Bridge'
						AND tm.name != 'CTI Route Point' AND tm.name != 'CTI Port'
						AND tm.name != 'MGCP Station' AND tm.name != 'Route List'
						AND tm.name != 'H.323 Gateway'
						AND tm.name != 'Music on Hold' 
						AND tm.name != 'Media Termination Point' 
						AND tm.name != 'Tone Announcement Player'
						AND tm.name != 'Cisco IOS Conference Bridge (HDV2)'
						AND tm.name != 'Cisco IOS Software Media Termination Point (HDV2)' 
						AND tm.name != 'Cisco IOS Media Termination Point (HDV2)' 
						AND tm.name != 'SIP Trunk' 
						AND (dp.name LIKE '%PH%' OR dp.name LIKE '%iMobile%'))
					GROUP BY cmg.name
					ORDER BY cmg.name""")

	if deviceQuery['return'] == None:
		return 'Unavailable'
	else:
		countByCmg = {}
		for cbdp in deviceQuery['return']['row']:
			countByCmg[cbdp[0].text] = int(cbdp[1].text)
	return countByCmg

def getCUCMOvaInfo(username, passwd, cucm_ip, logger):
	import math

	session = Session()
	session.verify = False
	session.auth = HTTPBasicAuth(username, passwd)
	transport = Transport(session=session, timeout=60)
	settings = Settings(strict=False, xml_huge_tree=True)
	client = Client(f'https://{cucm_ip}:8443/perfmonservice2/services/PerfmonService?wsdl', 
					settings=settings, transport=transport)
	service = client.create_service('{http://schemas.cisco.com/ast/soap}PerfmonBinding',
									f'https://{cucm_ip}:8443/perfmonservice2/services/PerfmonService')
	try:
		responseCpu = service.perfmonListInstance(Host=cucm_ip,Object ='Processor')
		ovaCpu = len(responseCpu) - 1
	except Fault as err:
		logger.error(f'Zeep error: perfmonListInstance: {err}' )

	try:
		responseMem = service.perfmonCollectCounterData(Host =cucm_ip, Object = 'Memory')
		responseMemLen = len(responseMem) -1
		n = 0
		while n <= responseMemLen:
			if responseMem[n]['Name']['_value_1'].__contains__('Total KBytes'):
				ovaMem = int(math.ceil(float(responseMem[n]['Value'])/1024000))
				break
			n += 1
	except Fault as err:
		logger.error(f'Zeep error: perfmonCollectCounterData: {err}')

	if ovaCpu == 4 and ovaMem == 8:
		return {'OVA_Size__c':True}
	else:
		return {'OVA_Size__c':False}

def updateSalesForce(sfInfo, sfDict, logger):

	session_id, instance = SalesforceLogin(username=sfInfo['SfUserId'],
											password=sfInfo['SfUserPwd'],
											security_token=sfInfo['SfSecToken'])
	sf = Salesforce(session_id=session_id, instance=instance)
	uc_clusters__c = SFType('UC_Clusters__c',session_id, instance)
	sfClusterId = sf.query(f"SELECT ID, Name, Cluster_ID__c FROM UC_Clusters__c WHERE Cluster_ID__c = '{sfDict['Cluster_ID__c']}'")
	try:
		uc_clusters__c.update(sfClusterId['records'][0]['Id'], sfDict)
	except Exception as e:
		if sfDict['Cluster_ID_Status__c'] == False:
			logger.error(f"Exception in updateSalesForce:  non-standard Cluster ID {sfDict['Cluster_ID__c']}, record not updated")

	return

def combineDict(logger, *args):
	sfDict = {}
	for arg in args:
		try:
			sfDict.update(arg)
		except Exception as e:
			logger.error(f'Combining dictionaries error encountered:  {e}')
	return sfDict