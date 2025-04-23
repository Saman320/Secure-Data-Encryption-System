import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json

# -------------------- Initialize session state --------------------
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "key" not in st.session_state:
    # Initialize or load the Fernet key
    # You can load the key from a file or generate it here
    st.session_state.key = Fernet.generate_key()  # You could replace this with a persistent key storage method.

cipher = Fernet(st.session_state.key)

# -------------------- Functions --------------------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(label, passkey):
    if label not in st.session_state.stored_data:
        return None

    hashed_input = hash_passkey(passkey)
    stored_entry = st.session_state.stored_data[label]

    if stored_entry["passkey"] == hashed_input:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(stored_entry["encrypted_text"].encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# -------------------- UI --------------------
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# ✅ STEP 2: Store Data Page
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")

    label = st.text_input("Enter a label for your data (e.g., email_backup):")
    user_data = st.text_area("Enter the data you want to store:")
    passkey = st.text_input("Enter your secret passkey:", type="password")

    if st.button("Encrypt & Save"):
        if label and user_data and passkey:
            encrypted_text = encrypt_data(user_data)
            hashed_passkey = hash_passkey(passkey)

            # Store encrypted data along with its label and passkey hash
            st.session_state.stored_data[label] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }

            # Save to a JSON file for persistence (optional)
            with open('stored_data.json', 'w') as f:
                json.dump(st.session_state.stored_data, f)

            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted_text, language='text')
        else:
            st.error("⚠️ Please fill all the fields.")

# ✅ STEP 3: Retrieve Data Page
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")

    label = st.text_input("Enter the label for your data:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if label and passkey:
            # Check if max attempts have been exceeded before proceeding
            if st.session_state.failed_attempts >= 3:
                st.warning("🚫 Too many failed attempts. Redirecting to Login page.")
                st.session_state.failed_attempts = 3  # Locking attempts after 3 failed attempts
                st.experimental_rerun()  # Redirect to login page immediately

            decrypted = decrypt_data(label, passkey)

            if decrypted:
                st.success("✅ Decryption Successful!")
                st.write("🔓 Decrypted Text:")
                st.code(decrypted)
            else:
                # Decrease the number of remaining attempts and display the error message
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")

                # Increment the failed attempts counter
                st.session_state.failed_attempts += 1
        else:
            st.error("⚠️ Please enter both label and passkey.")


# ✅ STEP 4: Login Page
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    st.info("You have exceeded maximum failed attempts. Please login to continue.")

    master_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_pass == "admin123":  # You can change this to any master password
            st.success("✅ Reauthorized successfully!")
            st.session_state.failed_attempts = 0
            st.success("🔁 Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password!")
