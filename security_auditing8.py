import subprocess
import json
import threading


def vault_key(result_list):
    checklist = {}
    checklist['check'] = 'VAULT_KEY_EXPIRY'
    check_vault_exists = subprocess.check_output(['az', 'keyvault', 'list', '--query', '[*].name'], shell=True)
    j_l = json.loads(check_vault_exists)
    if len(j_l) == 0:
        checklist['type'] = 'PASS'
        checklist['value'] = 'VAULT NOT SET UP FOR THE ACCOUNT'
        
        
    else:
        for vault in j_l:
            expiry = subprocess.check_output(['az', 'keyvault', 'key', 'list', '--vault-name', vault, '--query',
                                              '[].{kID:kid,expires:attributes.expires}'], shell=True)
            j_l1 = json.loads(expiry)
            l_d = j_l1[0]
            if l_d == '':
                checklist['type'] = 'PASS'
                checklist['value'] = 'No keys found in vault %s' % vault
                
                
            elif l_d['expires'] is None:
                checklist['type'] = 'WARNING'
                checklist['value'] = 'No expiry date set for key : %s' % l_d['kID']
                
                
            elif l_d['expires'] is not None:
                checklist['type'] = 'PASS'
                checklist['value'] = 'expiry date is %s for %s' % (l_d['expires'], vault)
                
                
            else:
                checklist['type'] = 'WARNING'
                checklist['value'] = 'Access Denied could not check for expiration in vault %s' % vault
    result_list.append(checklist)
                
def vault_secret(result_list):
    checklist = {}
    checklist['check'] = 'VAULT_SECRET_EXPIRY'
    check_vault_exists = subprocess.check_output(['az', 'keyvault', 'list', '--query', '[*].name'], shell=True)
    j_l = json.loads(check_vault_exists)
    if len(j_l) == 0:
        checklist['type'] = 'PASS'
        checklist['value'] = 'VAULT NOT SET UP FOR THE ACCOUNT'
        
        
    else:
        for vault in j_l:
            expiry = subprocess.check_output(['az', 'keyvault', 'secret', 'list', '--vault-name', vault, '--query',
                                              '[].{ID:id,expires:attributes.expires}'], shell=True)
            j_l1 = json.loads(expiry)
            l_d = j_l1[0]
            if l_d == '':
                checklist['type'] = 'PASS'
                checklist['value'] = 'No secret keys found in vault %s' % vault
                
                
            elif l_d['expires'] is None:
                checklist['type'] = 'WARNING'
                checklist['value'] = 'No expiry date set for secret : %s' % l_d['ID']
                
                
            elif l_d['expires'] is not None:
                checklist['type'] = 'PASS'
                checklist['value'] = 'expiry date is %s for %s' % (l_d['expires'], vault)
                
                
            else:
                checklist['type'] = 'WARNING'
                checklist['value'] = 'Access Denied could not check for expiration in vault %s' % (vault)
    result_list.append(checklist)

def audit5():
    result_list=[]
    t1 = threading.Thread(target=vault_key, args=(result_list,))
    t2 = threading.Thread(target=vault_secret, args=(result_list,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    return result_list

if __name__ == '__main__':
    audit5()
