import json
import os
import sys
import pandas as pd
from functools import reduce
from glob import glob
from pathlib import Path
from tabulate import tabulate

def sortListFileName(val):
    return val[0]

def behavior_summary(features, data):
    available = ['file_created','file_deleted', 'file_written', 'directory_created', 'regkey_opened', 'dll_loaded']
    result_list=['']#[data['target']['file']['name']]
    #print('File Name:',data['target']['file']['name'])    
    if not 'behavior' in data:
        result_list.append('behavior not found')
        result_list.append(' ')
        return result_list
    else:
        if not 'summary' in data['behavior']:            
            result_list.append(' ')
            result_list.append('No summary in behaviour')
            return result_list
    for x in available:
        #print(x)
        if x in features:
            category = data['behavior']['summary']
            if x in category:
                result_list.append(len(category[x]))
                
            else:                
                result_list.append('Not Found')
   
    return result_list

def filter(path):
    separator = "/" if os.name=="posix" else "\\"
    PATH = path
    result = [y for x in os.walk(PATH) for y in glob(os.path.join(x[0], '*.json'))]
    dataframes = list()
    features = ['procmemory', 'file', 'urls', 'proc_pid', 
    'network', 'udp', 'tcp', 'hosts', 'dns', 'request', 'domains', 
    'behavior', 
    'processes', 'pid', 'process_name', 'ppid', 
    'summary', 'file_created', 'file_deleted', 'dll_loaded', 'regkey_opened', 'command_line',        
    'regkey_read', 'regkey_written', 'file_written', 'directory_created']
    data_result=[]
    for report in result:
        with open(report) as f:
            data  = json.load(f)
       
        if 'behavior' in features:
          #  if 'processes' in features:
           #     behavior_processes(features,df_dataset,data)
            if 'summary' in features:
                data_result.append(behavior_summary(features,data))
       
    data_result.sort(key=sortListFileName)
    print(tabulate(data_result, headers=['file_Name','file_created','file_deleted', 'file_written', 'directory_created', 'regkey_opened', 'dll_loaded']))

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
    filter(sys.argv[1])
