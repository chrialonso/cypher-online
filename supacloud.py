import base64
import sqlite3
from tkinter import messagebox
import httpx
from encryptiono import generate_salt, hash_master_password

DB_FILE = "cyphero.db"

def supabase_register(email, password, supabase):
    """
    Register a new user with Supabase Auth.
    """
    try:
        result = supabase.auth.sign_up({
            "email": email,
            "password": password
        })

        if result.user:
            return True, result.user.id
        else:
            return False, None

    except Exception:
        print(f"Supabase registration failed.")
        return False, None

def supabase_login(email, password, supabase):
    """
    Authenticate an existing user with Supabase Auth.
    """
    try:
        result = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })

        if not result.user or not result.session:
            return None

        # Check if email is verified (if required by settings)
        if not result.user.email_confirmed_at:
            print("Warning: Email not verified")

        # Set the session immediately after successful login
        supabase.auth.set_session(result.session.access_token, result.session.refresh_token)

        return {"user_id": result.user.id, "session": result.session}

    except Exception as e:
        print(f"Supabase login failed. Check your credentials.")
        return None

def insert_user_into_table(supabase_user_id, email, master_password, supabase):
    """
    Insert a new user record into the Supabase "users" table.
    Uses a service-role key; should not be exposed in client apps.
    """
    try:
        salt = generate_salt()
        salt_b64 = base64.b64encode(salt).decode("utf-8")
        password_hash = hash_master_password(master_password)
        password_hash_str = password_hash.decode("utf-8")

        try:
            supabase.schema("api").from_("users").insert({
                "id": supabase_user_id,
                "username": email,
                "password_hash": password_hash_str,
                "salt": salt_b64
            }).execute()
        except httpx.ConnectError:
            messagebox.showwarning("No Internet Connection", "Could not reach Supabase")
            return

        print("Supabase user inserted successfully.")

    except Exception as e:
        print(f"Failed to add user into Supabase table: {e}")

def get_supabase_user_by_id(supabase_user_id, supabase):
    """
    Retrieve a single user record from the Supabase "users" table by UUID.
    """
    try:
        response = (supabase.schema("api").from_("users").select("*").eq("id", supabase_user_id).single().execute())

        if not response.data:
            print(f"No user data found for ID: {supabase_user_id}")
            return None

        return response.data
    except Exception as e:
        print(f"Error retrieving user from Supabase: {e}")
        return None

def get_local_passwords():
    """
    Fetch all locally stored passwords marked as syncable.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("select id, user_id, website, login_username, encrypted_password, created_on, last_modified, category, favorite, syncable from passwords where syncable = 1")
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_last_synced_time():
    """
    Retrieve the timestamp of the last successful sync from config.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("select value from config where key = 'last_synced'")
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else "2000-01-01 00:00:00"

def set_last_synced_time():
    """
    Update the config table with the current timestamp for 'last_synced'.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("insert or replace into config (key, value) values (?, current_timestamp)", ("last_synced",))
    conn.commit()
    conn.close()

def sync_modified_rows_to_supabase(supabase):
    """
    Push passwords modified since last sync to Supabase.
    """
    last_synced_time = get_last_synced_time()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("select id, user_id, website, login_username, encrypted_password, created_on, last_modified, category, favorite, syncable from passwords where last_modified > ? and syncable = 1", (last_synced_time,))
    rows = cursor.fetchall()
    conn.close()

    for row in rows:
        encrypted_password = base64.b64encode(row[4]).decode('utf-8')
        try:
            supabase.schema("api").from_("passwords").upsert({
                "id": row[0],
                "user_id": row[1],
                "website": row[2],
                "login_username": row[3],
                "encrypted_password": encrypted_password,
                "created_on": row[5],
                "last_modified": row[6],
                "category": row[7],
                "favorite": row[8],
                "syncable": row[9]
            }).execute()
        except httpx.ConnectError:
            messagebox.showwarning("No Internet Connection", "Could not reach Supabase")
            return
    set_last_synced_time()

def sync_all_to_supabase(supabase):
    """
    Push all local passwords to Supabase, regardless of modification time.
    """
    local_passwords = get_local_passwords()
    for row in local_passwords:
        encrypted_password = base64.b64encode(row[4]).decode("utf-8")
        try:
            supabase.schema("api").from_("passwords").upsert({
                "id": row[0],
                "user_id": row[1],
                "website": row[2],
                "login_username": row[3],
                "encrypted_password": encrypted_password,
                "created_on": row[5],
                "last_modified": row[6],
                "category": row[7],
                "favorite": row[8],
                "syncable": row[9]
            }).execute()
        except httpx.ConnectError:
            messagebox.showwarning("No Internet Connection", "Could not reach Supabase")
            return

def sync_from_supabase(user_id, supabase):
    """
    Fetch cloud-stored passwords for a user and merge them into local database.
    """
    try:
        response = supabase.schema("api").from_("passwords").select("*").eq("user_id", user_id).execute()
    except httpx.ConnectError:
        messagebox.showwarning("No Internet Connection", "Could not reach Supabase")
        return

    cloud_passwords = response.data
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    for entry in cloud_passwords:
        decoded_password = base64.b64decode(entry["encrypted_password"])
        cursor.execute("select last_modified, syncable from passwords where id = ?", (entry["id"],))
        row = cursor.fetchone()

        if not row:
            cursor.execute("insert into passwords(id, user_id, website, login_username, encrypted_password, created_on, last_modified, category, favorite, syncable) values (?, ?, ?, ?, ?, ?, ? ,?, ?, ?)",
                           (entry["id"], entry["user_id"], entry["website"], entry["login_username"], decoded_password, entry["created_on"], entry["last_modified"], entry["category"], entry["favorite"], entry["syncable"]))
        else:
            if entry["last_modified"] > row[0] or entry["syncable"] != row[1]:
                cursor.execute("update passwords set website = ?, login_username = ?, encrypted_password = ?, created_on = ?, last_modified = ?, category = ?, favorite = ?, syncable = ? where id = ?",(
                    entry["website"], entry["login_username"], decoded_password, entry["created_on"], entry["last_modified"], entry["category"], entry["favorite"], entry["syncable"], entry["id"]))

    conn.commit()
    conn.close()