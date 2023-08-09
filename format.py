def result(checklist):
    if checklist != None or len(checklist) != 0:
        for i in checklist:
            print("Check: ", i['check'])
            if i['type'] == "WARNING":
                print("Status: ", i['type'])
            else:
                print("Status: ", i['type'])
            print("Value: ", i['value'], end="\n-------------------------------------------\n")
