# C2 Sensor for C2LEMON
This is C2 sensor program for C2LEMON. The sensor is for collecting C2 servers'
responses, which can be visualized with C2LEMON app server. Responses are written in json format, and the specification is referenced at /models/schema.py.

## Policy
Concerning the potential risks of attempting to connect the sensor device to malicious hosts, this program is designed to run on UNIX-based platforms such as GNU/Linux or FreeBSD, on regular basis with systemd or cron. Running the program on Windows NT platforms or within non-DMZ network segment is highly risky and not favorable since it could cause a huge damage, not only to the sensor but also all hosts within the sensor's network segment.