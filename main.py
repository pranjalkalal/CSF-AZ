import art
import IAM_audit1 as IAM
import database_audit4 as database
import storage_account_auditing3 as storage
import VMs_auditing7 as vm
import security_auditing8 as secureA
import  networking_auditing6 as network
import  logging_monitoring_auditing5 as log_monitor
from printy import printy
import format
art.print1()

printy("----------- Starting IAM Checks -----------",'rB')
format.result(IAM.audit1())
printy("------------- IAM Checks Done -------------\n\n",'rB')
#2nd
printy("----------- Starting Storage Checks -----------",'rB')
format.result(storage.audit2())
printy("------------- Storage Checks Done -------------\n\n",'rB')
#3rd
printy("----------- Starting Database Checks -----------",'rB')
format.result(database.audit3())
printy("------------- Database Checks Done -------------\n\n",'rB')
#4th
printy("----------- Starting VM Checks -----------",'rB')
format.result(vm.audit4())
printy("------------- VM Checks Done -------------\n\n",'rB')
#5th
printy("----------- Starting Security Checks -----------",'rB')
format.result(secureA.audit5())
printy("------------- Security Checks Done -------------\n\n",'rB')
#6th
printy("----------- Starting Network Checks -----------",'rB')
format.result(network.audit6())
printy("------------- Network Checks Done -------------\n\n",'rB')
#7th
printy("----------- Starting Logging and Monitoring Checks -----------",'rB')
format.result(log_monitor.audit7())
printy("------------- Logging and Monitoring Checks Done -------------\n\n",'rB')
