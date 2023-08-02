# Import necessary libraries
from flask import Flask, render_template, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
import os
import re
import requests
from datetime import datetime

# Initialize Flask application
app = Flask(__name__)

# Set up SQLite database with SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/leandro/finalproject/whitelist.db'
app.config['SECRET_KEY'] = 'tele4642'  # Add a secret key for flash messages
db = SQLAlchemy(app)

# Define database model for MAC addresses
class MacAddress(db.Model):
    __tablename__ = 'mac_addresses'
    mac = db.Column(db.String, primary_key=True)

# Function to get ARP table and parse it
def get_arp_table():
    arp_table = os.popen('arp -n').read()  # Get ARP table as string
    ip_to_mac = {}

    # Parse ARP table, line by line
    for line in arp_table.split('\n')[1:]:
        parts = re.split(r'\s+', line)
        if len(parts) >= 3:
            ip = parts[0]
            mac = parts[2]
            ip_to_mac[ip] = mac

    return ip_to_mac

# Route for login page and form handling
@app.route('/', methods=['GET', 'POST'])
def login():
    # If form data is submitted
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name')
        email = request.form.get('email')
        card_number = request.form.get('card_number')
        cvv = request.form.get('cvv')
        expiry_date = request.form.get('expiry_date')

        # Perform basic form data validation
        # Invalid email address
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email address.')
            return render_template('login.html')

        # Invalid card number
        if not re.match(r'^\d{16}$', card_number):
            flash('Invalid card number. It should be 16 digits.')
            return render_template('login.html')

        # Invalid CVV
        if not re.match(r'^\d{3}$', cvv):
            flash('Invalid CVV. It should be 3 digits.')
            return render_template('login.html')

        # Invalid expiry date
        if not re.match(r'^\d{2}/\d{2}$', expiry_date):
            flash('Invalid expiry date. It should be in MM/YY format.')
            return render_template('login.html')

        # Check if the card's expiry date is in the future
        current_year = datetime.now().year % 100  # Get current year (last two digits)
        current_month = datetime.now().month  # Get current month
        expiry_month, expiry_year = map(int, expiry_date.split('/'))  # Split expiry date into month and year

        # Check if expiry year is less than current year or if the expiry year is the same and the expiry month is less than the current month
        if expiry_year < current_year or (expiry_year == current_year and expiry_month < current_month):
            flash('Invalid expiry date. The card has already expired.')
            return render_template('login.html')

        # Get client's IP address and MAC address
        ip_address = request.remote_addr
        mac_address = get_arp_table().get(ip_address)

        # If MAC address is found
        if mac_address is not None:
            # Check if MAC address is already whitelisted
            existing_mac = MacAddress.query.get(mac_address)
            # If not, add it to whitelist
            if existing_mac is None:
                mac = MacAddress(mac=mac_address)
                db.session.add(mac)
                db.session.commit()

                # Send API request to Ryu controller to allow traffic on port 443
                try:
                    response = requests.post("http://localhost:8080/flows/allow_port_443", json={"mac": mac_address, "dpid":"1"})
                    response.raise_for_status()  # Check if request was successful
                except requests.exceptions.RequestException as e:
                    flash(f'Error sending request to Ryu controller: {e}')
                    return render_template('login.html')
            
            # Redirect to internet access page
            return redirect('https://10.3.141.1')

    # If no form data submitted, render login page
    return render_template('login.html')

# Run the application
if __name__ == "__main__":
    # Start the Flask application
    app.run(host='10.3.141.1', port=5000)
