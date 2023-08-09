import subprocess
import json
import threading


def vm_agent(result_list):
    checklist = {}
    checklist['check'] = 'VM_AGENT'
    info = subprocess.check_output(['az', 'vm', 'list', '--query', '[*].[resourceGroup,name]'], shell=True)
    j_l = json.loads(info)
    if not j_l:
        checklist['type'] = 'PASS'
        checklist['value'] = 'No VMs to AUDIT'
        
        
    else:
        l_d = j_l[0]
        vm_exist = subprocess.check_output(
            ['az', 'vm', 'list', '-g', l_d[0],'--query', '[].[type,provisioningState]'],
            shell=True)
        j2_l2 = json.loads(vm_exist)
        l2_D2 = j2_l2[0]
        if vm_exist == '':
            checklist['type'] = 'WARNING'
            checklist['value'] = 'The VM %s does not have virtual agent enabled' % l_d[1]
            
            
        else:
            if l2_D2[1] == "Succeeded" and l2_D2[0] is not None:
                checklist['type'] = 'PASS'
                checklist['value'] = 'The VM %s does have virtual agent enabled' % l_d[1]
                
                
            else:
                checklist['type'] = 'WARNING'
                checklist['value'] = 'The VM %s does have provision state %s and virtualMachineExtensionType %s' % (
                    l_d[1], l2_D2[1], l2_D2[0])
                
    result_list.append(checklist)

def vm_os_disk(result_list):
    # Checking if OS disk encryption is enabled
    checklist = {}
    checklist['check'] = 'VM_OS_DISK_ENCRYPTION'
    info = subprocess.check_output(['az', 'vm', 'list', '--query', '[*].[resourceGroup,name]'], shell=True)
    j_l = json.loads(info)
    if not j_l:
        checklist['type'] = 'PASS'
        checklist['value'] = 'No VMs to AUDIT'
        
        
    else:
        l_d = j_l[0]
        encrypt = subprocess.check_output(['az', 'vm', 'list', '--query',
                                           '[].{encryption_settings:storageProfile.osDisk.encryptionSettings,'
                                           'disk_encryption:storageProfile.osDisk.diskEncryptionSet,'
                                           'security_profile:storageProfile.osDisk.security_profile}'],
                                          shell=True)
        j2_l2 = json.loads(encrypt)
        l2_d2 = j2_l2[0]
        if l2_d2['encryption_settings'] is None or l2_d2['disk_encryption'] is None or l2_d2[
            'security_profile'] is None:
            checklist['type'] = 'WARNING'
            checklist['value'] = 'The VM %s does not have OS DISK ENCRYPTION enabled' % l_d[1]
            checklist['status'] = l2_d2
            
            
        else:
            checklist['type'] = 'PASS'
            checklist['value'] = 'The VM %s does have OS DISK ENCRYPTION enabled' % l_d[1]

    result_list.append(checklist)


def approved_extension(result_list):
    
    checklist = {}
    checklist['check'] = 'APPROVED_EXTENSION'
    info = subprocess.check_output(['az', 'vm', 'list', '--query', '[*].[resourceGroup,name]'], shell=True)
    j_l = json.loads(info)
    if not j_l:
        checklist['type'] = 'PASS'
        checklist['value'] = 'No VMs to AUDIT'
        
        
    else:
        l_d = j_l[0]
        extensions = []
        check = subprocess.check_output(
            ['az', 'vm', 'extension', 'list', '--resource-group', l_d[0], '--vm-name', l_d[1], '--query', '[*].name'],
            shell=True)
        j2_l2 = json.loads(check)
        if len(extensions) == 0:
            checklist['type'] = "PASS"
            checklist['value'] = 'There are no extensions to evaluate'
            
            
        else:
            checklist['type'] = "WARNING"
            checklist['value'] = 'Please manually check for approval for these extensions'
            checklist['extensions'] = j2_l2
    result_list.append(checklist)

def audit4():
    result_list=[]
    t1 = threading.Thread(target=vm_agent,args=(result_list,))
    t2 = threading.Thread(target=vm_os_disk,args=(result_list,))
    t3 = threading.Thread(target=approved_extension,args=(result_list,))
    t1.start()
    t2.start()
    t3.start()
    t1.join()
    t2.join()
    t3.join()
    return result_list

if __name__ == '__main__':
    audit4()
