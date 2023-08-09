import json
import subprocess
import threading


def secure_transfer(result_list):
    # '''3.1: Checking if storage accounts have HTTPS only traffic enabled '''
    checklist = {}
    checklist['check'] = 'SECURE TRANSFER STORAGE ACCOUNT'
    https_enabled = subprocess.check_output(
        ['az', 'storage', 'account', 'list', '--query', '[].{Name:name,enable:enableHttpsTrafficOnly}'], shell=True)
    j_l = json.loads(https_enabled)  # json to list
    if not j_l:
        checklist['type'] = 'PASS'
        checklist['value'] = 'NO Storage account for AUDIT'
        
        
    else:
        l_D = j_l[0]  # list to dictionary
        if l_D['enable'] == 0:
            checklist['type'] = 'WARNING'
            checklist['value'] = 'The storage account %s does not have HTTPS only traffic enabled' % l_D['Name']
            
            
        else:
            checklist['type'] = 'PASS'
            checklist['value'] = 'The storage account %s does have HTTPS only traffic enabled' % l_D['Name']
            
    result_list.append(checklist)
def storage_service_encryption(result_list):
    # '''3.6: Checking if storage accounts has its associated BLOB service encryption enabled '''
    checklist = {}
    checklist['check'] = 'STORAGE SERVICE ENCRYPTION BLOB'
    storage_encryption = subprocess.check_output(['az', 'storage', 'account', 'list', '--query',
                                                  '[].{Name:name,Enable:encryption.services.blob.enabled,Location:primaryLocation}'],
                                                 shell=True)
    j_l = json.loads(storage_encryption)
    if not j_l:
        checklist['type'] = 'PASS'
        checklist['value'] = 'NO Storage account for AUDIT'
        
        
    else:
        l_D = j_l[0]
        checklist['region'] = l_D['Location']
        if l_D['Enable'] == 0:
            checklist['type'] = 'WARNING'
            checklist['value'] = 'The storage account %s does not have its associated BLOB service encryption enabled' % \
                                 l_D['Name']
            
            
        else:
            checklist['type'] = 'PASS'
            checklist['value'] = 'The storage account %s does have its associated BLOB service encryption enabled' % \
                                 l_D[
                                     'Name']

    result_list.append(checklist)
def default_network_access(result_list):
    # '''3.7 Ensure default network access rule for Storage Accounts is set to deny (Scored)'''
    checklist = {}
    checklist['check'] = 'default network access rule'
    access_rule = subprocess.check_output(['az', 'storage', 'account', 'list', '--query', '[*].networkRuleSet'],
                                          shell=True)
    j_l = json.loads(access_rule)
    if not j_l:
        checklist['type'] = 'PASS'
        checklist['value'] = 'NO Storage account for AUDIT'
        
        
    else:
        l_D = j_l[0]
        if l_D['defaultAction'] == 'Allow':
            checklist['type'] = 'WARNING'
            checklist['value'] = 'Default action is enable in your storage account'
            
            
        else:
            checklist['type'] = 'PASS'
            checklist['value'] = 'Default action is disable in your storage account'
    result_list.append(checklist)
            
def audit2():
    result_list=[]
    t1 = threading.Thread(target=secure_transfer,args=(result_list,))
    t2 = threading.Thread(target=default_network_access,args=(result_list,))
    t3 = threading.Thread(target=storage_service_encryption,args=(result_list,))
    t1.start()
    t2.start()
    t3.start()
    t1.join()
    t2.join()
    t3.join()
    return result_list

if __name__ == '__main__':
    audit2()
