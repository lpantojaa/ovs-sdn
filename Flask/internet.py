# Import necessary libraries
from flask import Flask, render_template
# Initialize Flask application
app = Flask(__name__)

app.config['SECRET_KEY'] = 'tele4642'  # Add a secret key for flash messages

# Route for internet access page
@app.route('/')
def internet():
    return render_template('internet.html')

# Run the application
if __name__ == "__main__":
    # Start the Flask application
    app.run(host='10.3.141.1', port=443, ssl_context=('server.crt', 'server.key'))
