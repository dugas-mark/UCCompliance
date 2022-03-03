def PhoneRIS(row):
    str_CustomerName = row[1]
    PhoneRIS.count_PhoneRIS = 'This report was not selected'
    PhoneRIS.str_FileSavePathPhoneRISCSV = (str_FileSavePath + str_CustomerName + '/' + TimeCapture.str_Time +
                                            '/' + str_CustomerName + '-CUCM-Phone-RIS-inventory.csv')
    if int(Collect_PHRIS) >> 0:
        node_names = []

        def getSubs():
            nodes = axl.list_process_nodes(AXL_Assembly.ucm)
            for node in nodes:
                node_names.append(node['name'])

        subs = getSubs()
        Phone_DevName = []
        PhoneRIS.count_PhoneRIS = 0
        node_loop = 0

        try:
            listPhones = AXL_Assembly.ucm.get_phones(tagfilter={'name': ''})
            # print(listPhones)
            for phone in listPhones:
                Phone_DevName.append(phone['name'])
            if int(verbose) == 3:
                print(Phone_DevName)
            phones = Phone_DevName
            limit = lambda phones, n=1000: [phones[i:i + n] for i in range(0, len(phones), n)]
            groups = limit(phones)
            if int(verbose) == 3:
                print(groups)
            device_RT_loop = 0
            with open(PhoneRIS.str_FileSavePathPhoneRISCSV, 'w', newline='', encoding='utf-8') as csvfile:
                w = csv.writer(csvfile)
                w.writerow(['Device Name', 'Description', 'Login User ID', 'Phone: Time Last Reset',
                            'Phone: Registered CallManager', 'Phone: IP Address', 'Phone: Active Load ID',
                            'Phone: Inactive Load ID'])
                if int(verbose) == 2:
                    print(
                        '\033[37mAbout to examine the node_names array in this list and analyze each one for registered devices: \n' +
                        str(node_names) + '\033[m')

                for ccmnode in node_names:
                    # ccmnode = list(ccmnode)
                    if int(verbose) == 3:
                        print('ccmnode in for loop = ' + str(ccmnode))
                    ccmnodes = []
                    ccmnodes.append(ccmnode)
                    # print('ccmnode  = ' + str(ccmnode))
                    # print('ccmnodes = ' + str(ccmnodes))
                    print('\n\n\nccmnode list = ' + str(ccmnodes))
                    if int(verbose) == 3:
                        print('ccmnode converted to list for analysis by registered = ' + str(ccmnodes))
                    try:
                        for group in groups:
                            try:
                                registered = RIS_Assembly.ris1.checkRegistration(group, ccmnodes)
                                if int(verbose) == 3:
                                    print(registered)
                                try:
                                    risnodeID_name = registered['CmNodes']['item'][0]['Name']
                                    if int(verbose) == 2:
                                        print('\033[37mNode Array Item ' + str(node_loop) + ': ' + str(
                                            risnodeID_name) + '::\033[m')
                                except Exception as risnodeID_fail:
                                    # print('Unable to find registered CCM instance')
                                    risnodeID_name = 'No Info Available'

                                len_risnodeID_name = len(risnodeID_name)
                                if len_risnodeID_name < 11:
                                    risNode_len_Spaces = 12 - int(len_risnodeID_name)
                                    risNode_len_Character = ' '
                                    risNode_graphic_space = risNode_len_Spaces * risNode_len_Character
                                    risNode_concatenation = risnodeID_name + risNode_graphic_space
                                else:
                                    risNode_concatenation = risnodeID_name[-12:] + '..'

                                for RIS_Device in tqdm(registered['CmNodes']['item'][0]['CmDevices']['item'],
                                                       desc=CustomerName.CustomerName_Concatenation + 'Phone Registered: ' +
                                                            risNode_concatenation) \
                                        if int(progress_indicator) == 1 \
                                        else registered['CmNodes']['item'][0]['CmDevices']['item']:
                                    # print('RIS_Device: ' + str(RIS_Device))
                                    try:
                                        time1 = RIS_Device['TimeStamp']
                                        time2 = int(time1)
                                        time3 = datetime.utcfromtimestamp(time2).strftime('%Y-%m-%d %H:%M:%S')
                                        if int(verbose) == 2:
                                            print('\033[37mRegistration Time(UTC):   ' + str(time3) + '\033[m')
                                    except Exception as ristime_fail:
                                        if int(verbose) == 2:
                                            print('Unable to parse out time')

                                    try:
                                        risuser = RIS_Device['LoginUserId']
                                    except Exception as risuser_fail:
                                        risuser = 'No Info Available'

                                    try:
                                        risregtime = time.strftime('%Y-%m-%d %H:%M:%S',
                                                                   time.localtime(RIS_Device['TimeStamp']))
                                        if int(verbose) == 2:
                                            print('\033[37mRegistration Time(Local): ' + risregtime + '\033[m')
                                    except Exception as risregtime_fail:
                                        if int(verbose) == 2:
                                            print('Unable to find last registered data')
                                        risregtime = 'No Info Available'

                                    try:
                                        risip = RIS_Device['IPAddress']['item'][0]['IP']
                                        if int(verbose) == 2:
                                            print('\033[37mDevice IP Address: ' + risip + '\033[m')
                                    except Exception as risip_fail:
                                        if int(verbose) == 2:
                                            print('Unable to find device IP address')
                                        risip = 'No Info Available'

                                    try:
                                        risactiveload = RIS_Device['ActiveLoadID']
                                        if int(verbose) == 2:
                                            print('\033[37mDevice Active load ID: ' + risactiveload + '\033[m')
                                    except Exception as risactiveload_fail:
                                        if int(verbose) == 2:
                                            print('Unable to find active load ID')
                                        risactiveload = 'No Info Available'

                                    try:
                                        risinactiveload = RIS_Device['InactiveLoadID']
                                        if int(verbose) == 2:
                                            print('\033[37mDevice Inactive Load ID: ' + risinactiveload + '\033[m')
                                    except Exception as risainctiveload_fail:
                                        if int(verbose) == 2:
                                            print('Unable to find inactive load ID')
                                        risinactiveload = 'No Info Available'

                                    try:
                                        risname = RIS_Device['Name']
                                        if int(verbose) == 2:
                                            print('\033[37mDevice Name: ' + risname + '\033[m')
                                    except Exception as risname_fail:
                                        if int(verbose) == 2:
                                            print('Unable to find device name')
                                        risname = 'No Info Available'

                                    try:
                                        risdescription = RIS_Device['Description']
                                        if int(verbose) == 2:
                                            print('\033[37mDevice Description: ' + risdescription + '\033[m\n\n')
                                    except Exception as risdescription_fail:
                                        if int(verbose) == 2:
                                            print('Unable to find description\n\n')
                                        risdescription = 'No Info Available'
                                    PhoneRIS.count_PhoneRIS = PhoneRIS.count_PhoneRIS + 1
                                    w.writerow(
                                        [risname, risdescription, risuser, risregtime, risnodeID_name, risip,
                                         risactiveload,
                                         risinactiveload])
                                node_loop = node_loop + 1
                            except Exception as group_in_groups_fail:
                                print('No devices registered on node instance, ' + str(risnodeID_name))
                    except Exception as Publisher_node_fail:
                        if int(verbose) == 2:
                            print('\033[37mNode Array Item ' + str(node_loop) + ': ' +
                                  str(node_names[int(
                                      node_loop)]) + ':: This is a publisher or non-call processing server..\033[m')
                            print('Error: ' + str(Publisher_node_fail) + '\n')
                        node_loop = node_loop + 1
            sleep(1)
            print('\033[32mData extraction was successful, and the following items were completed:\n'
                  '-Creation of ' + str_CustomerName + '-Phone-RIS-inventory.csv is complete\033[m\n\n')

        except Exception as Publisher_node_fail:
            print('Unable to grab RIS real time data, line number {}'.format(line_numb()) + '\n')
			
def checkRegistration(self, phones, subs):
    CmSelectionCriteria = {
                        "MaxReturnedDevices": "1000",
                        "DeviceClass": "Phone",
                        "Model": 255,
                        "Status": "Registered",
                        "NodeName": "",
                        "SelectBy": "Name",
                        "SelectItems": {
                                        "item": {"Item": ""}
                                        },
                        "Protocol": "Any",
                        "DownloadStatus": "Any"
                        }
    for sub in subs:
        CmSelectionCriteria['NodeName'] = sub
        CmSelectionCriteria['SelectItems']['item']['Item'] = ",".join(phones)
        reg = self.get_devices(**CmSelectionCriteria)
    return reg