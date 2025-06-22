import sqlite3

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')

    # Insert some default users (for demonstration purposes)
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', 'password123'))
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('user', 'pass'))
        conn.commit()
        print("Database initialized with default users.")
    except sqlite3.IntegrityError:
        print("Default users already exist.")
    except Exception as e:
        print(f"An error occurred during database initialization: {e}")
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
    