import os

def get_path(path:str, threat_id:str, observe_time:str, filename:str, agent_name:str, create_path:bool=False):
    '''Get a path for storing monitoring results

    Get a path accordingly, referencing observation time and threat ID.
    The directory for storing logs looks like this:
    root/
      ├ THREAT_1/
      |     └2021
      |        ├01
      |        | └20210131_1200_[agent_name].json
      |        | └20210131_1600_[agent_name].json
      |        | └20210131_2000_[agent_name].json
      |        | └...
      |        └02
      |         └...
      ├ THREAT_2/
      |     ├2020
      |     └2021
      ...

    Args:
        root (str): Root of the directory to store logs.
        observe_time (str): observation time in format: "%Y-%m-%dT%H:%M:%S".
        threat_id (str): ID assigned at the CSV file.
    
    Returns:

    '''
    # if directory does not exist, create
    observe_time_parsed = observe_time.split('-')
    try:
        year = observe_time_parsed[0]
        month = observe_time_parsed[1]
    except IndexError:
        print("observe_time format seems broken. It must be separated with -(hyphens).")
        return None
    path_list = [path, threat_id, year, month]
    abs_path = os.path.abspath("/".join(path_list))
    
    if not (os.path.isdir(abs_path)) and create_path:
        os.makedirs(abs_path)
        print("created the path:", abs_path)
    path_list.append(filename)
    return_val = os.path.join(abs_path, filename.replace(':', '_'))
    return return_val+"_" + agent_name + ".json"