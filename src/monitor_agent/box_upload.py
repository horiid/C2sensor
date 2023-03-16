from boxsdk import JWTAuth, Client

def validate_orgname(org: str):
    if org == "hitachi": return "hitachi-c2monitor"
    elif org == "tdu": return "tdu-c2monitor"
    else:
        print('An error with the provided organization name. Aborting.')
        raise ValueError

def find_box_folder(org: str, client: Client):
    folder_names = ["c2monitor", "public-c2monitor"]
    orgfolder = validate_orgname(org=org)
    # find c2monitor folder
    folder_id = 0
    while True:
        folder=client.folder(folder_id=folder_id)
        for item in folder.get_items():
            if item.name in folder_names:
                folder_id = item.id
            elif item.name == orgfolder:
                print("Found Folder: %s: %s"%(orgfolder, item.id))
                return item.id

def config(config_path):
    config = JWTAuth.from_settings_file(config_path)
    client = Client(config)
    return client

def find_and_create_folder_id(client, filename, threat_id):
    # Find the id of month path of agent/yyyy/mm/ on box. if found none,
    # the func creates a new folder.
    next_folder_id = find_box_folder("tdu", client) # initialization
    # find the store folder
    for count, foldername in enumerate(convert_to_folder_structure(filename, threat_id=threat_id)):
        create_folder = True
        items = client.folder(folder_id=next_folder_id).get_items()
        for item in items:
            if item.type == 'folder' and item.name == foldername:
                next_folder_id = item.id
                create_folder = False
                if count == 3:
                    return item.id # found month folder
                break
        # if not found, create new folder.
        if create_folder:
            subfolder = client.folder(next_folder_id).create_subfolder(foldername)
            print('Created subfolder "%s":%s'%(subfolder.name, subfolder.id))
            if count == 3: # Created month folder
                return subfolder.id
            else: # Created agent or year folder
                next_folder_id = subfolder.id
                create_folder = True

def convert_to_folder_structure(filename: str, threat_id):
    # separate yyyymmdd_agent.json to a list of [agent, threat_id, year, month]
    # filename e.g.: 20230315_0900_ISL01.json
    separated = filename.split('_')
    year = separated[0][:4]
    month = separated[0][4:6]
    agent = separated[2].split('.')[0]
    return [agent, threat_id, year, month]

def is_month_folder(foldername:str):
    month_list = [
        "01", "02", "03", "04",
        "05", "06", "07", "08",
        "09", "10", "11", "12"]
    return foldername in month_list