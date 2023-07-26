# Project Title: OpenFlow SDN WiFi AP

This is an OpenFlow Software-Defined Networking (SDN) application project which simulates an Internet environment, implements a payment page, and uses a Ryu controller to manage the network. 

## Dependencies
This project requires:
- Flask
- Ryu controller
- OpenvSwitch
- SQLite3

## Setup & Running the Project

### OpenvSwitch
Start by running the Open vSwitch.

```bash
sudo ./openvswitch-3.0.0/script
```

### Internet Simulator (Flask Application)
Navigate to the Flask directory of the project:

```bash
cd /home/leandro/finalproject/Flask
```

Export your Flask application:

```bash
export FLASK_APP=internet.py
```

Run your Flask application with SSL:

```bash
sudo -E flask run --host=10.3.141.1 --port=443 --cert=server.crt --key=server.key
```

### Payment Page (Flask Application)
Export the Flask application for the payment page:

```bash
export FLASK_APP=login.py
```

Run the Flask application:

```bash
flask run --host=10.3.141.1
```

### Ryu Controller
Run the Ryu controller to manage the network:

```bash
ryu-manager Ryu/controller.py 
```

### Checking Flows in br0
You can check the flows in br0 with the following command:

```bash
sudo ovs-ofctl dump-flows br0
```

### Checking Database
To interact with the SQLite database, use the sqlite3 command:

```bash
sqlite3 whitelist.db
```

To view all data in the `mac_addresses` table, use the SELECT SQL command:

```bash
select * from mac_addresses;
```