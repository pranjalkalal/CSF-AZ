import json
import subprocess
import threading


def log_profile(result_list):
    check_profile = subprocess.check_output(['az', 'monitor', 'log-profiles', 'list', '--query', '[].[id,name]'],
                                            shell=True)
    checklist = {}
    checklist['check'] = 'LOG PROFILE EXIST'
    j_l = json.loads(check_profile)
    if len(j_l) == 0:
        checklist['type'] = 'WARNING'
        checklist['value'] = 'There is currently no LOG PROFILE enabled'

    else:
        checklist['type'] = 'PASS'
        checklist['value'] = 'There is LOG PROFILE which exists'

    result_list.append(checklist)


def log_retention(result_list):
    retention_policy = subprocess.check_output(
        ['az', 'monitor', 'log-profiles', 'list', '--query', '[*].retentionPolicy.enabled'], shell=True)
    j_l = json.loads(retention_policy)
    checklist = {}
    checklist['check'] = 'LOG RETENTIONPOLICY ENABLE'
    if len(j_l) == 0:
        checklist['type'] = 'WARNING'
        checklist['value'] = 'There is currently no RETENTION policy applied to the LOG PROFILE'


    else:
        days = subprocess.check_output(['az', 'monitor', 'log-profiles', 'list', '--query', '[*].retentionPolicy.days'],
                                       shell=True)
        j_l1 = json.loads(days)
        l_d = j_l1[0]
        if l_d < 365:
            checklist['type'] = 'WARNING'
            checklist['value'] = 'The LOG RETENTION policy is currently lesser than 365 days'


        else:
            checklist['type'] = 'PASS'
            checklist['value'] = 'The  LOG RETENTION policy is good'

    result_list.append(checklist)


def alert_for_create_policy(result_list):
    resource_groups = subprocess.check_output(
        ['az', 'monitor', 'activity-log', 'alert', 'list', '--query', '[*].[resourceGroup]'], shell=True)
    checklist = {}
    j_l = json.loads(resource_groups)
    checklist['check'] = 'CREATE_POLICY_ASSIGNMENT'
    if len(j_l) == 0:
        checklist['type'] = 'PASS'
        checklist['value'] = 'There is No resource group found'


    else:
        l_d = j_l[0]
        for i in l_d:
            check1 = subprocess.check_output(
                ['az', 'monitor', 'activity-log', 'alert', 'list', '--resource-group', i, '--query',
                 '[?contains(condition.allOf[].equals, `Microsoft.Authorization/policyAssignments/write`)].name'],
                shell=True)
            j_l1 = json.loads(check1)
            if len(j_l1) == 0:
                checklist['type'] = 'WARNING'
                checklist['value'] = "The resource group %s has NO alert for Create Policy Assignment event" % i


            else:
                checklist['type'] = 'PASS'
                checklist['value'] = "The resource group %s has an alert for Create Policy Assignment event" % i

    result_list.append(checklist)


def alert_group_create_network(result_list):
    resource_groups = subprocess.check_output(
        ['az', 'monitor', 'activity-log', 'alert', 'list', '--query', '[*].[resourceGroup]'], shell=True)
    checklist = {}
    checklist['check'] = 'CREATE_NETWORK_GROUP'
    j_l = json.loads(resource_groups)
    if len(j_l) == 0:
        checklist['type'] = 'PASS'
        checklist['value'] = 'There is No resource group found'


    else:
        l_d = j_l[0]
        for i in l_d:
            check1 = subprocess.check_output(
                ['az', 'monitor', 'activity-log', 'alert', 'list', '--resource-group', i, '--query',
                 '[?contains(condition.allOf[].equals, `Microsoft.Network/networkSecurityGroups/write`)].name'],
                shell=True)
            j_l1 = json.loads(check1)
            if len(j_l1) == 0:
                checklist['type'] = 'WARNING'
                checklist[
                    'value'] = "The resource group %s has NO alert for Create or Update Network Security GROUP" % i


            else:
                checklist['type'] = 'PASS'
                checklist[
                    'value'] = "The resource group %s has an alert for Create or Update Network Security GROUP" % i

    result_list.append(checklist)


def alert_group_network_delete(result_list):
    resource_groups = subprocess.check_output(
        ['az', 'monitor', 'activity-log', 'alert', 'list', '--query', '[*].[resourceGroup]'], shell=True)
    checklist = {}
    checklist['check'] = 'DELETE_NETWORK_GROUP'
    j_l = json.loads(resource_groups)
    if len(j_l) == 0:
        checklist['type'] = 'PASS'
        checklist['value'] = 'There is No resource group found'


    else:
        l_d = j_l[0]
        for i in l_d:
            check1 = subprocess.check_output(
                ['az', 'monitor', 'activity-log', 'alert', 'list', '--resource-group', i, '--query',
                 '[?contains(condition.allOf[].equals, `Microsoft.Network/networkSecurityGroups/delete`)].name'],
                shell=True)
            j_l1 = json.loads(check1)
            if len(j_l1) == 0:
                checklist['type'] = 'WARNING'
                checklist['value'] = "The resource group %s has NO alert for Delete Network Security GROUP" % i


            else:
                checklist['type'] = 'PASS'
                checklist['value'] = "The resource group %s has an alert for Delete Network Security GROUP" % i

    result_list.append(checklist)


def alert_rule_network_create(result_list):
    resource_groups = subprocess.check_output(
        ['az', 'monitor', 'activity-log', 'alert', 'list', '--query', '[*].[resourceGroup]'], shell=True)
    checklist = {}
    checklist['check'] = 'CREATE_NETWORK_RULES'
    j_l = json.loads(resource_groups)
    if len(j_l) == 0:
        checklist['type'] = 'PASS'
        checklist['value'] = 'There is No resource group found'


    else:
        l_d = j_l[0]
        for i in l_d:
            check1 = subprocess.check_output(
                ['az', 'monitor', 'activity-log', 'alert', 'list', '--resource-group', i, '--query',
                 '[?contains(condition.allOf[].equals, `Microsoft.Network/securityRules/write`)].name'],
                shell=True)
            j_l1 = json.loads(check1)
            if len(j_l1) == 0:
                checklist['type'] = 'WARNING'
                checklist[
                    'value'] = "The resource group %s has NO alert for Create or Update Network Security GROUP RULE" % i


            else:
                checklist['type'] = 'PASS'
                checklist['value'] = "The resource group %s has an alert for Create or Update Security GROUP RULE" % i

    result_list.append(checklist)


def alert_rule_network_delete(result_list):
    resource_groups = subprocess.check_output(
        ['az', 'monitor', 'activity-log', 'alert', 'list', '--query', '[*].[resourceGroup]'], shell=True)
    checklist = {}
    checklist['check'] = 'DELETE_NETWORK_RULES'
    j_l = json.loads(resource_groups)
    if len(j_l) == 0:
        checklist['type'] = 'PASS'
        checklist['value'] = 'There is No resource group found'


    else:
        l_d = j_l[0]
        for i in l_d:
            check = subprocess.check_output(
                ['az', 'monitor', 'activity-log', 'alert', 'list', '--resource-group', i, '--query',
                 '[?contains(condition.allOf[].equals, `Microsoft.Network/networkSecurityGroups/delete`)].name'],
                shell=True)
            j_l1 = json.loads(check)
            if len(j_l1) == 0:
                checklist['type'] = 'WARNING'
                checklist['value'] = "The resource group %s has NO alert for Delete Network Security GROUP RULE" % i


            else:
                checklist['type'] = 'PASS'
                checklist['value'] = "The resource group %s has an alert for Delete Network Security GROUP RULE" % i

    result_list.append(checklist)


def alert_create_security(result_list):
    resource_groups = subprocess.check_output(
        ['az', 'monitor', 'activity-log', 'alert', 'list', '--query', '[*].[resourceGroup]'], shell=True)
    checklist = {}
    checklist['check'] = 'CREATE_SECURITY_SOLUTION'
    j_l = json.loads(resource_groups)
    if len(j_l) == 0:
        checklist['type'] = 'PASS'
        checklist['value'] = 'There is No resource group found'


    else:
        l_d = j_l[0]
        for i in l_d:
            check = subprocess.check_output(
                ['az', 'monitor', 'activity-log', 'alert', 'list', '--resource-group', i, '--query',
                 '[?contains(condition.allOf[].equals, `Microsoft.Security/securitySolutions/write`)].name'],
                shell=True)
            j_l1 = json.loads(check)
            if len(j_l1) == 0:
                checklist['type'] = 'WARNING'
                checklist['value'] = "The resource group %s has NO alert for Create/Update Security Solution" % i


            else:
                checklist['type'] = 'PASS'
                checklist['value'] = "The resource group %s has an alert for Create/Update Security Solution" % i

    result_list.append(checklist)


def alert_delete_security(result_list):
    resource_groups = subprocess.check_output(
        ['az', 'monitor', 'activity-log', 'alert', 'list', '--query', '[*].[resourceGroup]'], shell=True)
    checklist = {}
    checklist['check'] = 'DELETE_SECURITY_SOLUTION'
    j_l = json.loads(resource_groups)
    if len(j_l) == 0:
        checklist['type'] = 'PASS'
        checklist['value'] = 'There is No resource group found'


    else:
        l_d = j_l[0]
        for i in l_d:
            check = subprocess.check_output(
                ['az', 'monitor', 'activity-log', 'alert', 'list', '--resource-group', i, '--query',
                 '[?contains(condition.allOf[].equals, `Microsoft.Security/securitySolutions/delete`)].name'],
                shell=True)
            j_l1 = json.loads(check)
            if len(j_l1) == 0:
                checklist['type'] = 'WARNING'
                checklist['value'] = "The resource group %s has NO alert for DELETE Security Solution" % i


            else:
                checklist['type'] = 'PASS'
                checklist['value'] = "The resource group %s has an alert for DELETE Security Solution" % i

    result_list.append(checklist)


def alert_create_sql_rule(result_list):
    resource_groups = subprocess.check_output(
        ['az', 'monitor', 'activity-log', 'alert', 'list', '--query', '[*].[resourceGroup]'], shell=True)
    checklist = {}
    checklist['check'] = 'CREATE_SQL_FIREWALL_RULE'
    j_l = json.loads(resource_groups)
    if len(j_l) == 0:
        checklist['type'] = 'PASS'
        checklist['value'] = 'There is No resource group found'


    else:
        l_d = j_l[0]
        for i in l_d:
            check = subprocess.check_output(
                ['az', 'monitor', 'activity-log', 'alert', 'list', '--resource-group', i, '--query',
                 '[?contains(condition.allOf[].equals, `Microsoft.Sql/servers/firewallRules/write`)].name'],
                shell=True)
            j_l1 = json.loads(check)
            if len(j_l1) == 0:
                checklist['type'] = 'WARNING'
                checklist[
                    'value'] = "The resource group %s has NO alert for Create or Update SQL Server Firewall Rule events " % i


            else:
                checklist['type'] = 'PASS'
                checklist[
                    'value'] = "The resource group %s has an alert for Create or Update SQL Server Firewall Rule events" % i

    result_list.append(checklist)


def alert_delete_sql_rule(result_list):
    resource_groups = subprocess.check_output(
        ['az', 'monitor', 'activity-log', 'alert', 'list', '--query', '[*].[resourceGroup]'], shell=True)
    checklist = {}
    checklist['check'] = 'DELETE_SQL_FIREWALL_RULE'
    j_l = json.loads(resource_groups)
    if len(j_l) == 0:
        checklist['type'] = 'PASS'
        checklist['value'] = 'There is No resource group found'


    else:
        l_d = j_l[0]
        for i in l_d:
            check = subprocess.check_output(
                ['az', 'monitor', 'activity-log', 'alert', 'list', '--resource-group', i, '--query',
                 '[?contains(condition.allOf[].equals, `Microsoft.Sql/servers/firewallRules/delete`)].name'],
                shell=True)
            j_l1 = json.loads(check)
            if len(j_l1) == 0:
                checklist['type'] = 'WARNING'
                checklist[
                    'value'] = "The resource group %s has NO alert for Delete SQL Server Firewall Rule events " % i


            else:
                checklist['type'] = 'PASS'
                checklist['value'] = "The resource group %s has an alert for Delete SQL Server Firewall Rule events" % i

    result_list.append(checklist)


def alert_update_security_policy(result_list):
    resource_groups = subprocess.check_output(
        ['az', 'monitor', 'activity-log', 'alert', 'list', '--query', '[*].[resourceGroup]'], shell=True)
    checklist = {}
    checklist['check'] = 'UPDATE_SECURITY_POLICY'
    j_l = json.loads(resource_groups)
    if len(j_l) == 0:
        checklist['type'] = 'PASS'
        checklist['value'] = 'There is No resource group found'


    else:
        l_d = j_l[0]
        for i in l_d:
            check = subprocess.check_output(
                ['az', 'monitor', 'activity-log', 'alert', 'list', '--resource-group', i, '--query',
                 '[?contains(condition.allOf[].equals, `Microsoft.Security/policies/write`)].name'],
                shell=True)
            j_l1 = json.loads(check)
            if len(j_l1) == 0:
                checklist['type'] = 'WARNING'
                checklist['value'] = "The resource group %s has NO alert for changes in Security Policy events " % i


            else:
                checklist['type'] = 'PASS'
                checklist['value'] = "The resource group %s has an alert for changes in Security Policy events" % i

    result_list.append(checklist)


def category_set(result_list):
    category = subprocess.check_output(['az', 'monitor', 'log-profiles', 'list', '--query', '[*].categories'],
                                       shell=True)
    checklist = {}
    j_l = json.loads(category)
    checklist['check'] = 'categories set to Write, Delete and Action'
    if j_l is None:
        checklist['type'] = 'PASS'
        checklist['value'] = 'categories not exist'


    else:
        for i in j_l:
            if i in ['Write', 'Delete', 'Action']:
                checklist['type'] = 'PASS'
                checklist['value'] = 'category set to %s' % i


            else:
                checklist['type'] = 'Warning'
                checklist['value'] = 'categories not set to Write,Delete,Action'

    result_list.append(checklist)


def audit7():
    result_list = []
    t1 = threading.Thread(target=log_profile, args=(result_list,))
    t2 = threading.Thread(target=log_retention, args=(result_list,))
    t3 = threading.Thread(target=alert_for_create_policy, args=(result_list,))
    t4 = threading.Thread(target=alert_group_create_network, args=(result_list,))
    t5 = threading.Thread(target=alert_group_network_delete, args=(result_list,))
    t6 = threading.Thread(target=alert_rule_network_create, args=(result_list,))
    t7 = threading.Thread(target=alert_rule_network_delete, args=(result_list,))
    t8 = threading.Thread(target=alert_create_security, args=(result_list,))
    t9 = threading.Thread(target=alert_delete_security, args=(result_list,))
    t10 = threading.Thread(target=alert_create_sql_rule, args=(result_list,))
    t11 = threading.Thread(target=alert_delete_sql_rule, args=(result_list,))
    t12 = threading.Thread(target=alert_update_security_policy, args=(result_list,))
    t13 = threading.Thread(target=category_set, args=(result_list,))
    t1.start()
    t2.start()
    t3.start()
    t4.start()
    t5.start()
    t6.start()
    t7.start()
    t8.start()
    t9.start()
    t10.start()
    t11.start()
    t12.start()
    t13.start()
    t1.join()
    t2.join()
    t3.join()
    t4.join()
    t5.join()
    t6.join()
    t7.join()
    t8.join()
    t9.join()
    t10.join()
    t11.join()
    t12.join()
    t13.join()
    return result_list


if __name__ == '__main__':
    audit7()
