import subprocess
import threading


def no_guest_user(result_list):
    guest_user_list = subprocess.check_output(['az', 'ad', 'user', 'list', '--filter', "userType eq \'Guest\'"],
                                              shell=True)
    checklist = {}
    checklist['check'] = 'NO GUEST USER'
    if len(guest_user_list) > 4:
        checklist['type'] = 'WARNING'
        checklist['value'] = 'GUEST_USER found'

    else:
        checklist['type'] = 'PASS'
        checklist['value'] = 'NO_GUEST_USER found'

    result_list.append(checklist)


def custom_owner_role(result_list):
    definition_list = subprocess.check_output(['az', 'role', 'definition', 'list', '--name', 'Owner'], shell=True)
    checklist = {}
    checklist['check'] = 'CUSTOM OWNER ROLE'
    if len(definition_list) > 683:
        checklist['type'] = 'WARNING'
        checklist['value'] = 'Other Owner roles found'
    else:
        checklist['type'] = 'PASS'
        checklist['value'] = 'only one owner found'
    result_list.append(checklist)


def audit1():
    result_list = []
    t1 = threading.Thread(target=no_guest_user, args=(result_list,))
    t2 = threading.Thread(target=custom_owner_role, args=(result_list,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    return result_list


if __name__ == '__main__':
    audit1()
