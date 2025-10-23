import base64
import os
import shutil
import sqlite3
import time
import uuid
from urllib.parse import urlparse
from supacloud import sync_all_to_supabase, set_last_synced_time
from encryptiono import encrypt_password, decrypt_password, generate_salt, derive_key, hash_master_password, check_master_password

THEME_FILE = "theme.txt"
APPEAR_FILE = "appear.txt"
REMEMBER_ME_FILE = "remember_me.txt"
DB_FILE = 'cyphero.db'
DB_BACKUP_FILE = 'cyphero_backup.db'

# Preference file functions

def load_theme_preference():
    """
    Read and return the user's saved color theme from THEME_FILE.
    Returns default 'dark-blue' if no file exists.
    """
    if os.path.exists(THEME_FILE):
        with open(THEME_FILE, "r") as file:
            return file.read().strip()
    return "dark-blue"

def save_theme_preference(theme):
    """
    Save the given color theme string to THEME_FILE.
    """
    with open(THEME_FILE, "w") as file:
        file.write(theme)

def load_appear_preference():
    """
    Read and return the user's saved appearance mode from APPEAR_FILE.
    Returns default 'dark' if no file exists.
    """
    if os.path.exists(APPEAR_FILE):
        with open(APPEAR_FILE, "r") as file:
            return file.read().strip()
    return "dark"

def save_appear_preference(appear):
    """
    Save the given appearance mode string ('light', 'dark', etc.) to APPEAR_FILE.
    """
    with open(APPEAR_FILE, "w") as file:
        file.write(appear)

def save_username(remember_var, username):
    """
    Store or remove the remembered username based on remember_var state.
    If remember_var is 'on', writes username to REMEMBER_ME_FILE.
    Otherwise, deletes any existing REMEMBER_ME_FILE.
    """
    if remember_var.get() == "on":
        with open(REMEMBER_ME_FILE, "w") as file:
            file.write(username)
    else:
        if os.path.exists(REMEMBER_ME_FILE):
            os.remove(REMEMBER_ME_FILE)

def load_username(remember_var, username_entry):
    """
    Preload username from REMEMBER_ME_FILE into the GUI entry and set remember_var to 'on'.
    Does nothing if no saved username exists.
    """
    if os.path.exists(REMEMBER_ME_FILE):
        with open(REMEMBER_ME_FILE, "r") as file:
            saved_username = file.read().strip()
            username_entry.insert(0, saved_username)
            remember_var.set("on")

def backup_database():
    """
    Create a backup copy of the main database file.
    Returns True on success, False on I/O failure or if DB_FILE doesn't exist.
    """
    if os.path.exists(DB_FILE):
        try:
            print('Backing up existing database...')
            shutil.copy(DB_FILE, DB_BACKUP_FILE)
            return True
        except IOError as e:
            print(f'Could not backup database: {e}')
            return False

def database_exists():
    """
    On startup, checks to see if the database exists by checking to see
    if the 'users' table exists. Ensures that the database schema is correct.
    """
    if not os.path.exists(DB_FILE):
        return False
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""select name from sqlite_master where type = 'table' and name = 'users';""")
        table_exists = cursor.fetchall()
        conn.close()
        return bool(table_exists)
    except sqlite3.Error:
        print('Database is corrupted! Attempting recovery...')
        return False

def init_database():
    """
    Initialize the database schema by creating tables for users, passwords,
    login_attempts, and config if they do not already exist. Also inserts default config values.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
    create table if not exists users(
    id text primary key not null,
    username text unique not null,
    password_hash text not null,
    salt blob not null)
    """)

    cursor.execute("""
    create table if not exists passwords(
    id text primary key not null,
    user_id integer not null,
    website text not null,
    login_username text not null,
    encrypted_password blob not null,
    created_on timestamp default current_timestamp,
    last_modified timestamp default current_timestamp,
    category text not null,
    favorite integer default 0,
    syncable integer default 1,
    foreign key (user_id) references users(id) on delete cascade)
    """)

    cursor.execute("""
    create table if not exists login_attempts(
    username text primary key not null,
    attempts integer not null,
    last_attempt timestamp not null)
    """)

    cursor.execute("""
    create table if not exists config(
    key text primary key not null,
    value text not null)
    """)

    default_configs = {
        "max_attempts": "5",
        "lockout_time": "60"
    }

    for key, value in default_configs.items():
        cursor.execute("insert or ignore into config (key, value) values(?, ?)", (key, value))

    conn.commit()
    conn.close()

def get_config_value(key):
    """
    Retrieve an integer configuration value by key from the config table.
    Returns None if key is not found.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("select value from config where key = ?", (key,))
    result = cursor.fetchone()
    conn.close()
    return int(result[0]) if result else None

def create_user(username, master_password, supabase_user_id, salt = None):
    """
    Add a new user locally with hashed master password and salt.
    Returns False if username exists or insertion fails.
    """

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    #check if username is taken
    cursor.execute("select id from users where username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        return False #username exists

    if salt is None:
        salt = generate_salt()

    #hash the password
    password_hash = hash_master_password(master_password)

    try:
        cursor.execute("insert into users (id, username, password_hash, salt) values(?, ?, ?, ?)", (supabase_user_id, username, password_hash, salt))
        conn.commit()
        print(f'User {username} created successfully!')
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_user(username, password):
    """
    Validate given credentials against stored hash; return user_id if successful.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("select id, password_hash from users where username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            try:
                if check_master_password(password, user[1]):
                    return user[0]
            except ValueError:
                print('Error: Stored password is corrupted or invalid.')
                return None
    except sqlite3.Error as e:
        print(f'Database Error: {e}')
        return None
    except Exception as e:
        print(f'Unexpected Error: {e}')
        return None
    return None

def user_exists(username):
    """
    Return True if given username is found locally.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("select id from users where username = ?", (username,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

def get_user_salt(user_id):
    """
    Retrieve raw salt bytes for a user, or None if missing.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("select salt from users where id = ?", (user_id,))
    salt = cursor.fetchone()
    conn.close()

    if salt[0]:
        return salt[0]
    else:
        return None

def store_password(user_id, website, login_username, plain_password, category, encryption_key, top_level_domain):
    """
    Encrypt and save a new login entry under the given user.
    """

    website = normalize_website(website, top_level_domain)
    encrypted_password = encrypt_password(plain_password, encryption_key).encode()
    password_id = str(uuid.uuid4())
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        cursor.execute('insert into passwords (id, user_id, website, login_username, encrypted_password, category) values(?, ?, ?, ?, ?, ?)', (password_id, user_id, website, login_username, encrypted_password, category))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error: {e}")
    finally:
        cursor.close()
        conn.close()

def get_login_data(user_id, encryption_key, category = None, favorite = None):
    """
    Fetch and decrypt saved logins, optionally filtering by category or favorites.
    Each entry is returned as a tuple: (website, username, password, created_on, id, category, favorite, syncable, last_modified).
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    data = []
    query = 'SELECT website, login_username, encrypted_password, created_on, id, category, favorite, syncable, last_modified FROM passwords WHERE user_id = ?'
    params = [user_id]

    if category and category != "All" and category != "Favorites":
        query += ' AND category = ?'
        params.append(category)

    if category == "Favorites" or favorite == "True":
        query += ' AND favorite = 1'

    cursor.execute(query, params)

    rows = cursor.fetchall()
    for website, login_username, encrypted_password, creation_date, password_id, category, is_favorite, is_syncable, modified in rows:
        try:
            decrypted_password = decrypt_password(encrypted_password.decode(), encryption_key)
            data.append((website, login_username, decrypted_password, creation_date, password_id, category, is_favorite, is_syncable, modified))
        except Exception as e:
            print(f'Error decrypting password for {website}: {e}')
            data.append((website, login_username, 'Error: Cannot decrypt', creation_date, password_id, category, is_favorite, is_syncable, modified))
    conn.close()
    return data

def get_category(user_id, encryption_key):
    """
    Retrieve a list of (category, website) pairs for the given user.
    """
    if encryption_key is None:
        raise Exception('Authentication required.')

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    categories = []

    cursor.execute('select category, website from passwords where user_id = ?',  (user_id,))
    rows = cursor.fetchall()
    for category, website in rows:
        categories.append((category, website))
    conn.close()
    return categories

def delete_login(user_id, password_id):
    """
    Delete a login entry by its ID for the specified user.
    Commits immediately.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("delete from passwords where user_id = ? and id = ?", (user_id, password_id,))
    conn.commit()
    conn.close()

def edit_login(user_id, old_username, old_website, new_website, new_login_username, new_password, encryption_key):
    """
    Update an existing login's website, username, and password.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute('select id from passwords where user_id = ? and website = ? and login_username = ?', (user_id, old_website, old_username))
    result = cursor.fetchone()

    if not result:
        conn.close()
        return False, "Login not found"

    new_encrypted_password = encrypt_password(new_password, encryption_key).encode()

    try:
        cursor.execute("update passwords set website = ?, login_username = ?, encrypted_password = ?, last_modified = current_timestamp where user_id = ? and id = ?", (new_website, new_login_username, new_encrypted_password, user_id, result[0]))
        conn.commit()
        conn.close()
        return True, "Login updated successfully!"
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        print(f'Error Editing Login: {e}')
        return False

def change_master_password(user_id, old_password, new_password, supabase):
    """
    Change master password: re-encrypt all entries with a new key derived from new_password.
    Updates both local SQLite and remote Supabase records.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('select password_hash, salt from users where id = ? ', (user_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        return False, 'User not found'

    if not check_master_password(old_password, row[0]):
        conn.close()
        return False, 'Wrong password'

    old_encryption_key = derive_key(old_password, row[1])

    cursor.execute('select id, encrypted_password from passwords where user_id = ?', (user_id,))
    logins = cursor.fetchall()
    decrypted_passwords = {}

    for login_id, encrypted_password in logins:
        try:
            decrypted_passwords[login_id] = decrypt_password(encrypted_password.decode(), old_encryption_key)
        except Exception as e:
            print(f'Error decrypting password for {login_id}: {e}')
            conn.close()
            return False

    new_salt = os.urandom(16)
    new_salt_b64 = base64.b64encode(new_salt).decode("utf-8")
    new_encryption_key = derive_key(new_password, new_salt)

    for login_id, plain_password in decrypted_passwords.items():
        new_encrypted_password = encrypt_password(plain_password, new_encryption_key)
        cursor.execute("update passwords set encrypted_password = ? where id = ?", (new_encrypted_password, login_id))

    new_password_bytes = hash_master_password(new_password)
    new_password_hash = new_password_bytes.decode("utf-8")
    cursor.execute('update users set password_hash = ?, salt = ? where id = ?', (new_password_hash, new_salt_b64, user_id))
    conn.commit()
    conn.close()

    response = supabase.schema("api").from_("users").update({
        "password_hash": new_password_hash,
        "salt": new_salt_b64,}).eq("id", user_id).execute()

    if response.error:
        return False, f"Remote update failed: {response.error}"

    sync_all_to_supabase(supabase)
    set_last_synced_time()
    supabase.auth.sign_out()

    return True, None

def delete_master_user(user_id, password):
    """
    Permanently remove a user's account and all associated data.
    Confirms password before deletion.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    try:
        cursor.execute('select username, password_hash from users where id = ?', (user_id,))
        rows = cursor.fetchone()
        username = rows[0]
        stored_password = rows[1]

        if not username:
            return False, f'User {username} not found.'

        if check_master_password(password, stored_password):
            cursor.execute('delete from users where id = ?', (user_id,))
            conn.commit()
            print(f'User {username} deleted successfully!')
            return True
        else:
            print('Password does not match password stored in database.')
            return False
    except sqlite3.Error as e:
        print(f'User Deletion Error: {e}')
        return False
    finally:
        conn.close()

def get_login_info(username):
    """
    Check if a username is currently allowed to attempt login.
    Uses config values 'max_attempts' and 'lockout_time'.
    Returns False if locked out, True otherwise.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    now = int(time.time())
    cursor.execute("select attempts, last_attempt from login_attempts where username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result:
        if result[0] >= int(get_config_value("max_attempts")) and (now - result[1]) < get_config_value("lockout_time"):
            return False
    return True

def reset_attempts(username):
    """
    Clear all recorded login attempts for a user, resetting lockout state.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("delete from login_attempts where username = ?", (username,))
    conn.commit()
    conn.close()

def increment_attempts(username):
    """
    Increment failed login count and update timestamp.
    Inserts new record if none exists.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    now = int(time.time())

    cursor.execute("select * from login_attempts where username = ?", (username,))
    result = cursor.fetchone()

    if result:
        cursor.execute("update login_attempts set attempts = attempts + 1, last_attempt = ? where username = ?", (now, username))
    else:
        cursor.execute("insert into login_attempts(username, attempts, last_attempt) values (?, ?, ?)", (username, 1, now))
    conn.commit()
    conn.close()

def toggle_syncable(password_id, is_syncable, encryption_key):
    """
    Enable or disable cloud sync for a password entry.
    Requires valid encryption key to ensure user is authenticated.
    """
    if not encryption_key:
        raise Exception('Authentication required.')

    new_val = 1 if is_syncable.get() == "on" else 0

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("update passwords set syncable = ?, last_modified = current_timestamp where id = ?", (new_val, password_id))
    conn.commit()
    conn.close()

def toggle_favorite(password_id, is_favorite, encryption_key):
    """
    Mark or unmark a password entry as favorite.
    Requires valid encryption key for authentication.
    """
    if not encryption_key:
        raise Exception('Authentication required.')

    new_val = 1 if is_favorite.get() == "on" else 0

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("update passwords set favorite = ? where id = ?", (new_val, password_id))
    conn.commit()
    conn.close()

def normalize_website(website, top_level_domain):
    """
    Extract domain from URL or name, add a top-level domain if missing.
    """
    parsed_url = urlparse(website)
    domain = parsed_url.netloc if parsed_url.netloc else website
    domain = domain.replace("www.", "")

    if "." not in domain:
        return domain.lower() + top_level_domain

    return domain.lower()