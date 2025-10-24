
## Features

- **Cloud Sync with Supabase** – Securely sync your encrypted credentials across devices
- **AES-256-GCM Encryption** - Military-grade encryption standard
- **KDF-Based Key Derivation** - Secure password-based encryption keys
- **Client-Side Encryption** – Passwords are encrypted locally before upload; Supabase never sees plaintext
- **Cross-Device Access** – Sign in from anywhere and access your credentials securely
- **Category Organization** - Organize credentials by type
- **Favorites Organization** - Organize credentials by favorites

## Security Design & Features

- **Supabase Integration**  
  Provides cloud backup with real-time syncing across devices and secure user authentication.
  
- **Master Password–Derived Key**  
The encryption key is derived from your master password using a key-derivation function (KDF).
This means that only your password can unlock your encrypted data, not Cypher or Supabase.

- **Secure Cloud Sync**   
Encrypted credentials are synced with Supabase using authenticated sessions.
Data stored in the cloud remains encrypted, ensuring that only your device can decrypt it.

- **Cross-Device Access**  
When you log in on a new device, Cypher downloads your encrypted credentials
and decrypts them locally using your master password.
This keeps your data portable without sacrificing security.

- **Offline Compatibility**  
Works seamlessly with local storage; your credentials remain accessible even without an internet connection.

## Screenshots

<div align="center">
<img width="300" alt="image" src="https://github.com/user-attachments/assets/bdb01554-8318-47b5-9c58-9ed96bb4f7b6" />
  <p><em>Still access your credentials if you are offline</em></p>
</div>

<div align="center">
<img width="312" alt="image" src="https://github.com/user-attachments/assets/5c9e13ba-d2fb-40bc-ab7e-84f1e34c2d45" />
    <p><em>Show passwords organized by category</em></p>
  </div>

<div align="center">
<img width="312" alt="image" src="https://github.com/user-attachments/assets/64634274-4381-42f9-8287-86a6b2ef337d" />
  <p><em>Sync your credentials to and from Supabase</em></p>
</div>

<div align="center">
<img width="312" alt="image" src="https://github.com/user-attachments/assets/ed4b8a6e-c6cd-4138-a376-3d1abc518537" />
  <p><em>Register to Cypher and Supabase</em></p>
</div>

## About This Project
This project was built to expand the [Cypher Offline](https://github.com/chrialonso/cypher-offline) version to support cloud synchronization with Supabase. This project was built to learn and explore python, encryption, database security, Supabase, and GUI development.

## Disclaimer
This is a learning project. While it implements real security practices, it has not undergone professional security auditing.
