# Import necessary libraries
from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy

# Initialize Flask application
app = Flask(__name__)

# Set up SQLite database with SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/leandro/finalproject/whitelist.db'
app.config['SECRET_KEY'] = 'tele4642'  # Add a secret key for flash messages
db = SQLAlchemy(app)

# Define database model for MAC addresses
class MacAddress(db.Model):
    __tablename__ = 'mac_adresses'
    mac = db.Column(db.String, primary_key=True)

# Route for internet access page
@app.route('/')
def internet():
    # Check if device has been authenticated
    if not session.get('authenticated'):
        return redirect(url_for('login'))  # or some other response
    return render_template('internet.html')

# Run the application
if __name__ == "__main__":
    # Start the Flask application
    app.run(host='10.3.141.1', port=443, ssl_context=('server.crt', 'server.key'))
