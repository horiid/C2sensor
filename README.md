# C2 Sensor for C2LEMON
This is C2 sensor program for C2LEMON. The sensor is for collecting C2 servers'
responses, which can be visualized with C2LEMON app server. Responses are written in json format, and the specification is referenced at /models/schema.py.

## Policy
Concerning the potential risks of attempting to connect the sensor device to possible malicious hosts, this program is designed to run on UNIX-based platforms periodically using systemd or cron. available on Windows however, by using .bat file and time scheduler. Running the program on Windows NT platform or within monitored network segment is risky and not recommended since it could cause a unnecessary alerts, or worse.
