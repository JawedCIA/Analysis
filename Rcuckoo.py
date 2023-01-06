import json
import os
import sys
import pathlib
import pandas as pd
from functools import reduce
from glob import glob
from pathlib import Path
from tabulate import tabulate


def sortListFileName(val):
    return val[0]

def get_items(test_dict, lvl):
  
    # querying for lowest level
    if lvl == 0:
        yield from ((key, val) for key, val in test_dict.items()
                    if not isinstance(val, dict))
    else:
  
        # recur for inner dictionaries
        yield from ((key1, val1) for val in test_dict.values()
                    if isinstance(val, dict) for key1, val1 in get_items(val, lvl - 1))
        
#print Dlls as union
def malware_dlls(data_result_behavior_summaryDLL,Folderpath):
    working_Folder=(pathlib.PurePath(Folderpath)).name
    print(working_Folder)
    print("===================================")
    rows_in_ddls=len(data_result_behavior_summaryDLL)
    #print("rows:",rows_in_ddls)
    dlls=""
    dlls_list=[]
    #print(data_result_behavior_summaryDLL[0][1])
    for row in range(0,rows_in_ddls,2):
        #print("\n",data_result_behavior_summaryDLL[row][1])        
        union = list(set().union(data_result_behavior_summaryDLL[row][1],data_result_behavior_summaryDLL[row+1][1]))
    #jobs = [job.replace(',','\n') for job in union]
      
    dlls='\n'.join(map(str,union))
    #print("\n")
    #print()
    print(dlls)
    print("===================================")
    
#Sum the colmn list value
def sum_list(data_list_result):    
    col_rows_data_result=len(data_list_result[0])     
    #print("Total Column:",col_rows_data_result)   
    total_list=['Total']
    for col in range(1,col_rows_data_result,1):
        value=0 
        for item in data_list_result:
            item_col_len=len(item)
            #print("Colm length:",item_col_len)
            if item_col_len > col:
                if item[col]!=None:
                   #print("Item value:",int(item[col])) 
                   value=value+int(item[col])
               
        total_list.append(value)    
    data_list_result.append(total_list)
    return data_list_result

#Collect network result
def network(features, data):
    available = ['udp', 'tcp', 'hosts', 'request', 'domains']
    result_list_network=[data['target']['file']['name']]
    if not 'network' in data:
        result_list_network.append(None)
        return result_list_network
    for x in available:
        if x in features:
            category = data['network']
            if x in category:
                result_list_network.append(len(category[x]))
            elif x=='request':
                if 'dns' in category:
                    network_dns_requests = []
                    for item in data['network']['dns']:
                        network_dns_requests.append(item['request'])
                    result_list_network.append(network_dns_requests)
                else:
                    result_list_network.append(None)
            else:
                result_list_network.append(None)
    #print(result_list_network)
    return result_list_network
    #print(tabulate(result_list_network, headers = available, tablefmt='grid'))

#Collect behaviour API Call Count and Dlls loaded
def behavior_apistats_dlls(features, data):
    available = ['apistats']
    result_list=[data['target']['file']['name']]    
    if not 'behavior' in data:
        result_list.append(None)        
        return result_list
    else:
        if not 'apistats' in data['behavior']:            
            result_list.append(None)
            return result_list
    for x in available:
        #print(x)
        if x in features:
            category = data['behavior']['apistats']
            count_apistats = len(category)
            #print(category)
            #print(count_apistats)
            if count_apistats >= 1:
                totalApiCount=0
                for apistats in category:
                    totalApiCount=totalApiCount+int(apistats)                    
                result_list.append(totalApiCount)
            else:                
                result_list.append(len(category))

    result_list.append(behavior_summary_dllsCount(data))
   # print(result_list)
    return result_list

#Collect behaviour API Call Details
def behavior_apistats_details(features, data):
    available = ['apistats']
    result_list=[data['target']['file']['name']]    
    if not 'behavior' in data:
        result_list.append(None)        
        return result_list
    else:
        if not 'apistats' in data['behavior']:            
            result_list.append(None)
            return result_list
    for x in available:
        #print(x)
        if x in features:
            category = data['behavior']['apistats']
            count_apistats = len(category)
            #print("Type of a: ", type(category))
            # calling function
            res = get_items(category, 1)                       
            #result_list.append(str(list(res)).replace(',','\n'))
            result_list.append(list(res))
            #print("\n\n",category)
            #result_list=category
    #print("\n result List: ", result_list)        
    return result_list

#Collect Behaviour Summary result
def behavior_summary(features, data):
    available = ['file_created','file_deleted', 'file_written', 'directory_created', 'regkey_opened', 'dll_loaded']
    result_list=[data['target']['file']['name']]
    #print('File Name:',data['target']['file']['name'])    
    if not 'behavior' in data:
        result_list.append(None)
        #result_list.append(None)
        return result_list
    else:
        if not 'summary' in data['behavior']:            
            result_list.append(None)
            #result_list.append(None)
            return result_list
    for x in available:
        #print(x)
        if x in features:
            category = data['behavior']['summary']
            if x in category:
                result_list.append(len(category[x]))                
            else:                
                result_list.append(None)
   
    return result_list

#Collect Behaviour Summary result for DLL
def behavior_summary_DLL(features, data):
    available = ['dll_loaded']
    result_list=[data['target']['file']['name']]
    #print('File Name:',data['target']['file']['name'])    
    if not 'behavior' in data:
        result_list.append([])
        return result_list
    else:
        if not 'summary' in data['behavior']:            
            result_list.append([])
            return result_list
    for x in available:
        if x in features:
            category = data['behavior']['summary']
            if x in category:
                result_list.append(category[x])             
            else:                
                result_list.append([])
   # print(result_list)
    return result_list

#Collect DLLs List 
def behavior_summary_dllsCount(data):
    total_dlls=0
    if not 'behavior' in data:      
        return total_dlls
    else:
        if not 'summary' in data['behavior']:                        
            return total_dlls
   
        
    category = data['behavior']['summary']
    if 'dll_loaded' in category:
        total_dlls = len(category['dll_loaded'])               

    return total_dlls


#Collect Behaviour Summary result for connect host and API
def behavior_summary_host_ip(features, data):
    available = ['connects_host','connects_ip']
    result_list=[data['target']['file']['name']]
    #print('File Name:',data['target']['file']['name'])    
    if not 'behavior' in data:
        result_list.append([])
        return result_list
    else:
        if not 'summary' in data['behavior']:            
            result_list.append([])
            return result_list
    for x in available:
        if x in features:
            category = data['behavior']['summary']
            if x in category:
                result_list.append(category[x])             
            else:                
                result_list.append([])
   # print(result_list)
    return result_list

#Calling function based on results
def workingWithReport(path):
    separator = "/" if os.name=="posix" else "\\"
    PATH = path
    #print(PATH)
    result = [y for x in os.walk(PATH) for y in glob(os.path.join(x[0], '*.json'))]
    dataframes = list()
    features = ['procmemory', 'file', 'urls', 'proc_pid', 
    'network', 'udp', 'tcp', 'hosts', 'dns', 'request', 'domains', 
    'behavior', 'apistats',
    'processes', 'pid', 'process_name', 'ppid', 
    'summary', 'file_created', 'file_deleted', 'dll_loaded', 'regkey_opened', 'command_line',        
    'regkey_read', 'regkey_written', 'file_written', 'directory_created','connects_host','connects_ip']
    data_result_behavior_summary=[]
    data_result_behavior_summaryDLL=[]
    data_result_behavior_summaryHostIP=[]
    data_result_network=[]
    data_result_apistats_dlls=[]
    data_result_apistats_details=[]
    for report in result:
        with open(report) as f:
            data  = json.load(f)
            #print(report)
        if 'network' in features:
            data_result_network.append(network(features,data))
        if 'behavior' in features:
            if 'apistats' in features:
                data_result_apistats_dlls.append(behavior_apistats_dlls(features,data))
                data_result_apistats_details.append(behavior_apistats_details(features,data))
            if 'summary' in features:
                data_result_behavior_summary.append(behavior_summary(features,data))
                data_result_behavior_summaryDLL.append(behavior_summary_DLL(features,data))
                data_result_behavior_summaryHostIP.append(behavior_summary_host_ip(features,data))

        
    print("\nBeviour Summary Results:")
    #print(tabulate(data_result_behavior_summary, headers=['file_Name','file_created','file_deleted', 'file_written', 'directory_created', 'regkey_opened', 'dll_loaded'],tablefmt='grid'))
    print(tabulate(sum_list(data_result_behavior_summary), headers=['file_Name','file_created','file_deleted', 'file_written', 'directory_created', 'regkey_opened', 'dll_loaded'],tablefmt='grid'))
    print("\nNetwork Results:") 
    print(tabulate(data_result_network, headers=['file_Name','udp','tcp', 'hosts', 'request', 'domains'], tablefmt='grid'))   
    print("\nBeviour Host and IP Results:")
    print(tabulate(data_result_behavior_summaryHostIP, headers=['file_Name','connects_host','connects_ip'], tablefmt='grid'))
    print("\nBeviour APISTATS and DLLS Results:")        
    print(tabulate(sum_list(data_result_apistats_dlls), headers=['file_Name','apistats','dll_loaded'], tablefmt='grid'))
    print("\nDlls Imported in reports")
    #print(tabulate(data_result_behavior_summaryDLL, headers=['file_Name','DLLS'], tablefmt='grid'))
    #Print Union dlls imported
    malware_dlls(data_result_behavior_summaryDLL,PATH)
    #print(data_result_apistats)
    print("\n API Details")
    print(tabulate(data_result_apistats_details, headers=['file_Name','API'], tablefmt='grid'))


#mains
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Usage: python3 Rcuckoo.py "/my/directory/with/json/files"')
        sys.exit(0)
    if not isinstance(sys.argv[1],str):
        print('Enter a valid string!')
        
        sys.exit(0)
    if not os.path.exists(sys.argv[1]):
        print('The directory "'+str(sys.argv[1])+'" does not exist, make sure to use quotation marks around the directory string.')
        sys.exit(0)
    if not os.path.isdir(sys.argv[1]):
        print(str(sys.argv[1])+' is not a directory, make sure to use quotation marks around the directory string.')
        sys.exit(0)
    workingWithReport(sys.argv[1])
