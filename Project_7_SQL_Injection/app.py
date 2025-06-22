from flask import Flask, render_template, request, redirect, url_for
import sqlite3 # <--- ENSURE THIS LINE IS PRESENT AND CORRECTLY SPELLED

app = Flask(__name__) # <--- ENSURE THIS LINE IS PRESENT AND CORRECTLY SPELLED

# Function to get a database connection
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row # This allows access to columns by name
    return conn

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        # --- VULNERABLE CODE - FOR DEMONSTRATION ONLY ---
        # query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        # print(f"DEBUG: Executing query (vulnerable): {query}") # For demonstration
        # cursor = conn.cursor()
        # cursor.execute(query)
        # -------------------------------------------------

        # --- SECURE CODE - Uncomment this section and comment the vulnerable one above to fix ---
        query = "SELECT * FROM users WHERE username = ? AND password = ?" # This is the parameterized query
        print(f"DEBUG: Executing query (secure): {query} with params ('{username}', '{password}')") # For demonstration
        cursor = conn.cursor()
        cursor.execute(query, (username, password)) # Pass parameters as a tuple here
        # --------------------------------------------------------------------------------------

        user = cursor.fetchone()
        conn.close()

        if user:
            return render_template('dashboard.html', username=user['username'])
        else:
            message = "Invalid Credentials"
    return render_template('login.html', message=message)

if __name__ == '__main__':
    # --- TEMPORARY DEBUGGING CODE - Simplified startup check ---
    print("DEBUG: Attempting to start Flask server...")
    try:
        app.run(debug=True)
    except Exception as e:
        print(f"ERROR: Flask app.run() failed: {e}")
    # --- END TEMPORARY DEBUGGING CODE ---