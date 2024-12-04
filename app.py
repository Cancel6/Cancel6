from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os
from g4f.client import Client  

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configure the PostgreSQL database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://les_posgres_user:gYpuFme1C2tPvrpXWusQCvegnOCGIaYv@dpg-ct7r5a23esus73a1762g-a/les_posgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# # Configure the database connection
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:new_password@localhost/ocean_current_app'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Secret key for session management
app.secret_key = 'lester'

# Initialize the database
db = SQLAlchemy(app)

# Initialize g4f Client
g4f_client = Client()

# Initialize OAuth
oauth = OAuth(app)

def describe_direction(velocity, direction):
    """
    Generate a natural language description of a current's velocity and direction.

    Parameters:
        velocity (float): Speed of the current in kilometers per hour.
        direction (float): Direction of the current in degrees.

    Returns:
        str: A descriptive summary of the current's velocity and direction.
    """
    directions = [
        (0, 22.5, "North"),
        (22.5, 67.5, "Northeast"),
        (67.5, 112.5, "East"),
        (112.5, 157.5, "Southeast"),
        (157.5, 202.5, "South"),
        (202.5, 247.5, "Southwest"),
        (247.5, 292.5, "West"),
        (292.5, 337.5, "Northwest"),
        (337.5, 360, "North")
    ]
    return determine_direction(velocity, direction, directions)

def determine_direction(velocity, direction, directions):
    """
    Determine the descriptive phrase for the current's velocity and direction.

    Args:
        velocity (float): Speed of the current in kilometers per hour.
        direction (float): Direction of the current in degrees (0–360°).
        directions (list of tuples): List of tuples containing ranges and labels for directions.
                                     Each tuple should be in the format (start, end, label).

    Returns:
        str: A descriptive phrase about the current's movement.
    """
    # Match the direction angle to the range and find the label
    direction_label = next((label for start, end, label in directions if start <= direction < end), None)
    
    # Generate the descriptive phrase
    if direction_label:
        return (f"The current is moving at {velocity} kilometers per hour in a direction of {direction}°, "
                f"which is towards the {direction_label}. This indicates a flow heading primarily {direction_label.lower()}ward.")
    else:
        return "Invalid direction input. Direction must be between 0 and 360 degrees."

google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    redirect_uri='http://localhost:5000/google/callback',
    client_kwargs={'scope': 'openid profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True)  # Not required for Google login
    google_id = db.Column(db.String(255), unique=True, nullable=True)

# Create the database tables (if they don't already exist)
with app.app_context():
    db.create_all()

# Google Login Route
@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

# Google OAuth callback
@app.route('/login/callback')
def google_callback():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()

    # Check if user already exists
    user = User.query.filter_by(google_id=user_info['id']).first()
    if user:
        # If user exists, log them in
        session['user_id'] = user.id
        session['username'] = user.username
    else:
        # If user does not exist, register them
        new_user = User(username=user_info['email'], google_id=user_info['id'])
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.id
        session['username'] = new_user.username

    return redirect(url_for('home_page'))

# Route for the home page (Map page)
@app.route('/')
def home_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('map.html', username=session['username'])

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user exists
        user = User.query.filter_by(username=username).first()
        if not user:
            return "User not found!"
        
        # Verify the password
        if not check_password_hash(user.password, password):
            return "Invalid password!"

        # Store user info in session
        session['user_id'] = user.id
        session['username'] = user.username
        return redirect(url_for('home_page'))
    
    return render_template('login.html')

# Route for registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return "Passwords do not match!"
        
        # Hash the password for security
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Username already exists!"
        
        # Save the user to the database
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return "Registration successful! You can now log in."
    
    return render_template('register.html')

@app.route('/get_ocean_currents', methods=['GET'])
def get_ocean_currents():
    # Mock data for velocity visualization layer
    ocean_data = {
        "data": [
            {"lat": 9.41, "lon": 126.82, "velocity_u": 0.4, "velocity_v": 0.2},
            {"lat": 9.43, "lon": 126.85, "velocity_u": 0.3, "velocity_v": 0.1},
        ],
        "header": {
            "parameterCategory": 2,
            "parameterNumber": 2,
            "parameterUnit": "m/s",
            "parameterNumberName": "Surface current",
        }
    }
    return jsonify(ocean_data)

@app.route('/fetch_ocean_data', methods=['GET'])
def fetch_ocean_data():
    latitude = request.args.get('latitude', type=float)
    longitude = request.args.get('longitude', type=float)

    current_api_url = f"https://barmmdrr.com/connect/gmarine_api?latitude={latitude}&longitude={longitude}&current=ocean_current_velocity,ocean_current_direction&timezone=Asia/Singapore"
    hourly_api_url = f"https://barmmdrr.com/connect/gmarine_api?latitude={latitude}&longitude={longitude}&hourly=ocean_current_velocity,ocean_current_direction&timezone=Asia/Singapore"

    try:
        current_response = requests.get(current_api_url)
        hourly_response = requests.get(hourly_api_url)

        if current_response.status_code != 200 or hourly_response.status_code != 200:
            return jsonify({"error": "Failed to fetch data from external APIs"}), 500

        current_data = current_response.json()
        hourly_data = hourly_response.json()

        # Extract velocity and direction
        velocity = current_data.get("current", {}).get("ocean_current_velocity", "N/A")
        direction = current_data.get("current", {}).get("ocean_current_direction", "N/A")

        # Generate description
        description = describe_direction(
            float(velocity) if velocity != "N/A" else 0,
            float(direction) if direction != "N/A" else 0
        )

        return jsonify({
            "current": {
                "velocity": velocity,
                "direction": direction
            },
            "hourly": hourly_data.get("hourly", {}),
            "description": description
        })

    except requests.RequestException as e:
        return jsonify({"error": f"Failed to fetch data: {str(e)}"}), 500
    
# Route to handle AI message using g4f
@app.route('/fetch_ai_message', methods=['GET'])
def fetch_ai_message():
    prompt = request.args.get('prompt')
    if not prompt:
        return jsonify({"error": "No prompt provided"}), 400

    # Add a request to keep the response short
    modified_prompt = f"{prompt} Please provide a short response for an analysis if thats the current velocity and direction."

    try:
        # Use the g4f client to generate a chat response
        response = g4f_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": modified_prompt}],
        )
        ai_message = response.choices[0].message.content

        return jsonify({"message": ai_message})

    except Exception as e:
        return jsonify({"error": f"Failed to generate AI response: {str(e)}"}), 500



@app.route('/fetch_historical_data', methods=['GET'])
def fetch_historical_data():
    latitude = request.args.get('latitude', type=float)
    longitude = request.args.get('longitude', type=float)

    # URL to fetch historical hourly data
    hourly_api_url = f"https://barmmdrr.com/connect/gmarine_api?latitude={latitude}&longitude={longitude}&hourly=ocean_current_velocity,ocean_current_direction&timezone=Asia/Singapore"

    try:
        # Fetch hourly data
        response = requests.get(hourly_api_url)
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch historical data from external API"}), 500

        hourly_data = response.json().get("hourly", {})
        time_series = hourly_data.get("time", [])
        velocity_series = hourly_data.get("ocean_current_velocity", [])
        direction_series = hourly_data.get("ocean_current_direction", [])

        # Limit data to the last 5 days (assuming hourly data)
        if len(time_series) > 120:  # 5 days * 24 hours = 120 data points
            time_series = time_series[-50:]
            velocity_series = velocity_series[-50:]
            direction_series = direction_series[-50:]

        return jsonify({
            "time": time_series,
            "velocity": velocity_series,
            "direction": direction_series
        })

    except requests.RequestException as e:
        return jsonify({"error": f"Error fetching historical data: {str(e)}"}), 500


@app.route('/map')
def map_page():
    return render_template('map.html')

@app.route('/map')
def map():
    username = session.get('username', 'Guest')  # Replace 'Guest' with a default value if no user is logged in
    return render_template('map.html', username=username)



@app.route('/animation')
def animation_page():
    # Check if the user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('animation.html')


if __name__ == '__main__':
    import os
    if os.getenv('FLASK_ENV') == 'development':
        app.run(debug=True)  # Flask development server
    else:
        from waitress import serve
        serve(app, host='0.0.0.0', port=5000)  # Waitress for production or local testing
