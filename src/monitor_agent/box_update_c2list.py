import configutils
from boxsdk import JWTAuth, Client
from pprint import pprint

# update c2list by downloading c2 list .csv file from indicator/ folder on box.
def download_c2list():
    config_ini = "config/config.ini"
    config = configutils.ConfigManager(conf_path=config_ini)
    client = Client(JWTAuth.from_settings_file(config.box_auth))

    tree = ["c2monitor", "indicator", "c2.isl.tdu.csv"]
    c2_list_path = config.c2_list
    folder_id = 0
    for level, name in enumerate(tree):
        items  =client.folder(folder_id).get_items()
        for item in items:
            if item.name == name and item.type == 'folder':
                folder_id = item.id
            elif item.name == name and item.type == 'file':
                box_file = client.file(file_id=item.id).get()
                pprint(box_file)
                with open(config.c2_list, 'w', newline='') as f:
                    f.write(box_file.content().decode('utf-8'))
                return True
            
        

download_c2list()