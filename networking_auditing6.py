import subprocess
import json
import threading


def rdp_public (result_list):
    network_list = subprocess.check_output(["az", "network", "nsg", "list", "--query", "[*].[name]"], shell=True)
    checklist = {}
    checklist['check'] = 'PUBLIC_RDP_ACCESS'
    j_l = json.loads(network_list)
    if j_l == '':
        checklist['type'] = 'PASS'
        checklist['value'] = 'nsg group not found'
        
        
    else:
        lines = subprocess.check_output(["az", "network", "nsg", "list", "--query",
                                         "[].{Name:name,access:securityRules[].access,destination_port:securityRules[].destinationPortRange,direction:securityRules[].direction,protocol:securityRules[].protocol,sourceAddress_prefix:securityRules[].sourceAddressPrefix}"],
                                        shell=True)
        j_l1 = json.loads(lines)
        for i in j_l1:
            flag = 0
            l_d = i
            if l_d['destination_port'] == ['3389'] and l_d['access'] == ['Allow'] and l_d['direction'] == [
                'Inbound'] and \
                    l_d['sourceAddress_prefix'] in [['*'], ['0.0.0.0'], ['internet'], ['any'], ['<nw>/0'], ['/0'],
                                                    ['']]:
                checklist['value'] = "Please check %s network group for RDP public access" % l_d['Name']
                checklist['type'] = 'WARNING'
                
                
                flag = 1
            if flag == 0:
                checklist['value'] = "The network group %s does not allow public RDP access" % l_d['Name']
                checklist['type'] = 'PASS'
    result_list.append(checklist)
                
def ssh_public (result_list):
    network_list = subprocess.check_output(["az", "network", "nsg", "list", "--query", "[*].[name]"], shell=True)
    checklist = {}
    checklist['check'] = 'PUBLIC_SSH_ACCESS'
    j_l = json.loads(network_list)
    if j_l == '':
        checklist['type'] = 'PASS'
        checklist['value'] = 'nsg group not found'
        
        
    else:
        lines = subprocess.check_output(["az", "network", "nsg", "list", "--query",
                                         "[].{Name:name,access:securityRules[].access,destination_port:securityRules[].destinationPortRange,sourceAddress_prefix:securityRules[].sourceAddressPrefix}"],
                                        shell=True)
        j_l1 = json.loads(lines)
        for i in j_l1:
            l_d = i
            if l_d['destination_port'] == ['22'] and l_d['access'] == ['Allow'] and l_d['sourceAddress_prefix'] in [
                ['*'], ['0.0.0.0'], ['internet'], ['any'], ['<nw>/0'], ['/0'], '']:
                checklist['value'] = "Please check %s network group for SSH public access" % l_d['Name']
                checklist['type'] = 'WARNING'
                
                
            else:
                checklist['value'] = "The network group %s does not allow public SSH access" % l_d['Name']
                checklist['type'] = 'PASS'
    result_list.append(checklist)

def network_watcher (result_list):
    check = subprocess.check_output(['az', 'network', 'watcher', 'list'], shell=True)
    j_l = json.loads(check)
    checklist = {}
    checklist['check'] = 'NETWORK_WATCHER'
    if len(j_l) == 0:
        checklist['type'] = 'WARNING'
        checklist['value'] = 'Network Watcher is not enabled for your account'
        
        
    else:
        checklist['type'] = 'PASS'
        checklist['value'] = 'Network Watcher is enabled for your account'
    result_list.append(checklist)

def audit6():
    result_list=[]
    t1 = threading.Thread(target=rdp_public, args=(result_list,))
    t2 = threading.Thread(target=ssh_public, args=(result_list,))
    t3 = threading.Thread(target=network_watcher, args=(result_list,))
    t1.start()
    t2.start()
    t3.start()
    t1.join()
    t2.join()
    t3.join()
    return result_list

if __name__ == '__main__':
    audit6()
