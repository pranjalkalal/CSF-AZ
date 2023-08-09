import subprocess
import json
import threading


def sql_db_audit   (result_list):
    checklist = {}
    checklist['check'] = 'SQL_DB_AUDIT'
    check_server_exists = subprocess.check_output(
        ['az', 'sql', 'server', 'list', '--query', '[*].[name,resourceGroup]'], shell=True)
    j_l = json.loads(check_server_exists)
    if not j_l:
        checklist['type'] = 'PASS'
        checklist['value'] = 'No SQL servers/DB to AUDIT'
         
         
    else:
        l_D = j_l[0]
        databases = subprocess.check_output(
            ['az', 'sql', 'db', 'list', '--server', l_D[0], '--resource-group', l_D[1], '--query', '[*].name'],
            shell=True)
        j2_l2 = json.loads(databases)
        for d in j2_l2:
            audit_policy = subprocess.check_output(
                ['az', 'sql', 'db', 'audit-policy', 'show', '--resource-group', l_D[1], '--server', l_D[0], '--name', d,
                 '--query', 'state'], shell=True)
            j3_l3 = json.loads(audit_policy)
            if j3_l3 == "Disabled":
                checklist['type'] = 'WARNING'
                checklist['value'] = 'The SQL DB %s on server %s does not have AUDIT Policy enabled' % (d, l_D[0])
                 
                 
            else:
                checklist['type'] = 'PASS'
                checklist['value'] = 'The SQL DB %s on server %s does have AUDIT Policy enabled' % (d, l_D[0])
                 
    result_list.append(checklist)

def sql_db_threat   (result_list):
    # '''Checking if SQL DB has Threat Detection enabled'''
    checklist = {}
    checklist['check'] = 'SQL_DB_THREAT_DETECTION'
    check_server_exists = subprocess.check_output(
        ['az', 'sql', 'server', 'list', '--query', '[*].[name,resourceGroup]'], shell=True)
    # print(l_D)
    j_l = json.loads(check_server_exists)
    if not j_l:
        checklist['type'] = 'PASS'
        checklist['value'] = 'No SQL servers/DB to AUDIT'
         
         
    else:
        l_D = j_l[0]
        databases = subprocess.check_output(
            ['az', 'sql', 'db', 'list', '--server', l_D[0], '--resource-group', l_D[1], '--query', '[*].name'],
            shell=True)
        j2_l2 = json.loads(databases)
        for d in j2_l2:
            threat_policy = subprocess.check_output(
                ['az', 'sql', 'db', 'threat-policy', 'show', '--resource-group', l_D[1], '--server', l_D[0], '--name',
                 d, '--query', 'state'], shell=True)
            j3_l3 = json.loads(threat_policy)
            if j3_l3 == "Disabled":
                checklist['type'] = 'WARNING'
                checklist['value'] = 'The SQL DB %s on server %s does not have AUDIT Policy enabled' % (d, l_D[0])
                 
                 
            else:
                checklist['type'] = 'PASS'
                checklist['value'] = 'The SQL DB %s on server %s does have AUDIT Policy enabled' % (d, l_D[0])

    result_list.append(checklist)

def sql_db_disabled_alert   (result_list):
    # Checking if SQL DB has Threat Detection enabled'''
    checklist = {}
    checklist['check'] = 'SQL_DB_DISABLED_ALERT'
    check_server_exists = subprocess.check_output(
        ['az', 'sql', 'server', 'list', '--query', '[*].[name,resourceGroup]'], shell=True)
    j_l = json.loads(check_server_exists)
    if not j_l:
        checklist['type'] = 'PASS'
        checklist['value'] = 'No SQL servers/DB to AUDIT'
         
         
    else:
        l_D = j_l[0]
        databases = subprocess.check_output(
            ['az', 'sql', 'db', 'list', '--server', l_D[0], '--resource-group', l_D[1], '--query', '[*].name'],
            shell=True)
        j2_l2 = json.loads(databases)
        for d in j2_l2:
            threat_policy = subprocess.check_output(
                ['az', 'sql', 'db', 'threat-policy', 'show', '--resource-group', l_D[1], '--server', l_D[0], '--name',
                 d, '--query', 'disabledAlerts'], shell=True)
            j3_l3 = json.loads(threat_policy)
            if j3_l3[0] == "":
                checklist['type'] = 'WARNING'
                checklist['value'] = 'The SQL DB %s on server %s has some of the alerts disabled' % (d, l_D[0])
                 
                 
            else:
                checklist['type'] = 'PASS'
                checklist['value'] = 'The SQL DB %s on server %s does not have alerts disabled' % (d, l_D[0])

    result_list.append(checklist)

def sql_db_send_email   (result_list):
    # Checking if SQL DB has any email alerts enabled'''
    checklist = {}
    checklist['check'] = 'SQL_DB_EMAIL_ALERT'
    check_server_exists = subprocess.check_output(
        ['az', 'sql', 'server', 'list', '--query', '[*].[name,resourceGroup]'], shell=True)
    j_l = json.loads(check_server_exists)
    if not j_l:
        checklist['type'] = 'PASS'
        checklist['value'] = 'No SQL servers/DB to AUDIT'
         
         
    else:
        l_D = j_l[0]
        databases = subprocess.check_output(
            ['az', 'sql', 'db', 'list', '--server', l_D[0], '--resource-group', l_D[1], '--query', '[*].name'],
            shell=True)
        j2_l2 = json.loads(databases)
        for d in j2_l2:
            threat_policy = subprocess.check_output(
                ['az', 'sql', 'db', 'threat-policy', 'show', '--resource-group', l_D[1], '--server', l_D[0], '--name',
                 d, '--query', 'emailAddresses'], shell=True)
            j3_l3 = json.loads(threat_policy)
            if j3_l3[0] == "":
                checklist['type'] = 'WARNING'
                checklist['value'] = 'The SQL DB %s on server %s has some no email set for alerts' % (d, l_D[0])
                 
                 
            else:
                checklist['type'] = 'PASS'
                checklist['value'] = 'The SQL DB %s on server %s has some email set for alerts' % (d, l_D[0])

    result_list.append(checklist)

def sql_db_email_admin   (result_list):
    # Checking if SQL DB has any Admin email alerts enabled'''
    checklist = {}
    checklist['check'] = 'SQL_DB_EMAIL_ADMIN'
    check_server_exists = subprocess.check_output(
        ['az', 'sql', 'server', 'list', '--query', '[*].[name,resourceGroup]'], shell=True)
    j_l = json.loads(check_server_exists)
    if not j_l:
        checklist['type'] = 'PASS'
        checklist['value'] = 'No SQL servers/DB to AUDIT'
         
         
    else:
        l_D = j_l[0]
        databases = subprocess.check_output(
            ['az', 'sql', 'db', 'list', '--server', l_D[0], '--resource-group', l_D[1], '--query', '[*].name'],
            shell=True)
        j2_l2 = json.loads(databases)
        for d in j2_l2:
            threat_policy = subprocess.check_output(
                ['az', 'sql', 'db', 'threat-policy', 'show', '--resource-group', l_D[1], '--server', l_D[0], '--name',
                 d, '--query', 'emailAccountAdmins'], shell=True)
            j3_l3 = json.loads(threat_policy)
            if j3_l3 == 0:
                checklist['type'] = 'WARNING'
                checklist['value'] = 'The SQL DB %s on server %s has no Admin email set for alerts' % (d, l_D[0])
                 
                 
            else:
                checklist['type'] = 'PASS'
                checklist['value'] = 'The SQL DB %s on server %s has some Admin email set for alerts' % (d, l_D[0])

    result_list.append(checklist)

def sql_db_encryption   (result_list):
    # Checking if SQL DB has Threat Detection enabled\n\n'''
    checklist = {}
    checklist['check'] = 'SQL_DB_DATA_ENCRYPTION'
    check_server_exists = subprocess.check_output(
        ['az', 'sql', 'server', 'list', '--query', '[*].[name,resourceGroup]'], shell=True)
    j_l = json.loads(check_server_exists)
    if not j_l:
        checklist['type'] = 'PASS'
        checklist['value'] = 'No SQL servers/DB to AUDIT'
         
         
    else:
        l_D = j_l[0]
        databases = subprocess.check_output(
            ['az', 'sql', 'db', 'list', '--server', l_D[0], '--resource-group', l_D[1], '--query', '[*].name'],
            shell=True)
        j2_l2 = json.loads(databases)
        # print(j2_l2)
        for d in j2_l2:
            threat_policy = subprocess.check_output(
                ['az', 'sql', 'db', 'tde', 'show', '--resource-group', l_D[1], '--server', l_D[0], '--database', d,
                 '--query', 'state'], shell=True)
            j3_l3 = json.loads(threat_policy)
            if j3_l3 == 'Disabled':
                checklist['type'] = 'WARNING'
                checklist['value'] = 'The SQL DB %s on server %s has Transparent Data Encryption disabled' % (d, l_D[0])
                 
                 
            else:
                checklist['type'] = 'PASS'
                checklist['value'] = 'The SQL DB %s on server %s has Transparent Data Encryption enabled' % (d, l_D[0])
    result_list.append(checklist)
                 
def sql_db_audit_retention   (result_list):
    # Checking if SQL DB has AUDIT log retention policy greater than 90 days\n\n'''
    checklist = {}
    checklist['check'] = 'SQL_DB_AUDIT_RETENTION'
    check_server_exists = subprocess.check_output(
        ['az', 'sql', 'server', 'list', '--query', '[*].[name,resourceGroup]'], shell=True)
    j_l = json.loads(check_server_exists)
    if not j_l:
        checklist['type'] = 'PASS'
        checklist['value'] = 'No SQL servers/DB to AUDIT'
         
         
    else:
        l_D = j_l[0]
        databases = subprocess.check_output(
            ['az', 'sql', 'db', 'list', '--server', l_D[0], '--resource-group', l_D[1], '--query', '[*].name'],
            shell=True)
        j2_l2 = json.loads(databases)
        for d in j2_l2:
            audit_policy = subprocess.check_output(
                ['az', 'sql', 'db', 'audit-policy', 'show', '--resource-group', l_D[1], '--server', l_D[0], '--name',
                 d, '--query', 'retentionDays'], shell=True)
            j3_l3 = json.loads(audit_policy)
            if int(j3_l3) <= 90:
                checklist['type'] = 'WARNING'
                checklist['value'] = 'The SQL DB %s on server %s has AUDIT log retention policy lesser than 90 days' % (
                    d, l_D[0])
                 
                 
            else:
                checklist['type'] = 'PASS'
                checklist['value'] = 'The SQL DB %s on server %s has AUDIT log retention policy greater than 90 day' % (
                    d, l_D[0])

    result_list.append(checklist)

def sql_db_threat_retention   (result_list):
    # Checking if SQL DB has THREAT log retention policy greater than 90 days
    checklist = {}
    checklist['check'] = 'SQL_DB_THREAT_RETENTION'
    check_server_exists = subprocess.check_output(
        ['az', 'sql', 'server', 'list', '--query', '[*].[name,resourceGroup]'], shell=True)
    j_l = json.loads(check_server_exists)
    if not j_l:
        checklist['type'] = 'PASS'
        checklist['value'] = 'No SQL servers/DB to AUDIT'
         
         
    else:
        l_D = j_l[0]
        databases = subprocess.check_output(
            ['az', 'sql', 'db', 'list', '--server', l_D[0], '--resource-group', l_D[1], '--query', '[*].name'],
            shell=True)
        j2_l2 = json.loads(databases)
        for d in j2_l2:
            threat_policy = subprocess.check_output(
                ['az', 'sql', 'db', 'threat-policy', 'show', '--resource-group', l_D[1], '--server', l_D[0], '--name',
                 d, '--query', 'retentionDays'], shell=True)
            j3_l3 = json.loads(threat_policy)
            if int(j3_l3) <= 90:
                checklist['type'] = 'WARNING'
                checklist[
                    'value'] = 'The SQL DB %s on server %s has THREAT log retention policy lesser than 90 days' % (
                    d, l_D[0])
                 
                 
            else:
                checklist['type'] = 'PASS'
                checklist[
                    'value'] = 'The SQL DB %s on server %s has THREAT log retention policy greater than 90 day' % (
                    d, l_D[0])

    result_list.append(checklist)

def audit3():
    result_list=[]
    t1 = threading.Thread(target=sql_db_audit, args=(result_list,))
    t2 = threading.Thread(target=sql_db_threat, args=(result_list,))
    t3 = threading.Thread(target=sql_db_audit_retention, args=(result_list,))
    t4 = threading.Thread(target=sql_db_threat_retention, args=(result_list,))
    t5 = threading.Thread(target=sql_db_disabled_alert, args=(result_list,))
    t6 = threading.Thread(target=sql_db_send_email, args=(result_list,))
    t7 = threading.Thread(target=sql_db_email_admin, args=(result_list,))
    t8 = threading.Thread(target=sql_db_encryption, args=(result_list,))
    t1.start()
    t2.start()
    t3.start()
    t4.start()
    t5.start()
    t6.start()
    t7.start()
    t8.start()
    t1.join()
    t2.join()
    t3.join()
    t4.join()
    t5.join()
    t6.join()
    t7.join()
    t8.join()
    return result_list


if __name__ == '__main__':
    audit3()
