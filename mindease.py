import os
import json
import nltk
import bcrypt
from dotenv import load_dotenv
from datetime import datetime
from nltk.sentiment.vader import SentimentIntensityAnalyzer
from openai import OpenAI
import sqlite3
import logging
import re
import msvcrt

nltk.download('vader_lexicon', quiet=True)
analyzer = SentimentIntensityAnalyzer()
load_dotenv()

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "mindease.log")
DB_FILE = os.path.join(LOG_DIR, "mindease.db")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("openai").setLevel(logging.WARNING)

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
if not OPENROUTER_API_KEY:
    logger.critical("OPENROUTER_API_KEY not found in .env file. Exiting.")
    print("Error: OPENROUTER_API_KEY not found. Please create a .env file with OPENROUTER_API_KEY='your_key'.")
    exit(1)

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=OPENROUTER_API_KEY,
)

OPENROUTER_MODEL = "google/gemini-2.5-flash"
EXIT_COMMANDS = ["!stop", "!quit", "!end", "!exit"]
MAX_CHAT_HISTORY_FOR_LLM = 8

def input_password(prompt="Password: "):
    print(prompt, end='', flush=True)
    password = ''
    while True:
        char = msvcrt.getch()
        if char in {b'\r', b'\n'}:
            print('')
            break
        elif char == b'\x08':
            if password:
                password = password[:-1]
                print('\b \b', end='', flush=True)
        elif char == b'\x03':
            raise KeyboardInterrupt
        else:
            try:
                decoded = char.decode('utf-8')
                password += decoded
                print('*', end='', flush=True)
            except:
                continue
    return password

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def setup_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        hashed_password TEXT NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        message_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        sentiment_score REAL,
        risk_level TEXT DEFAULT 'Low Risk',
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    )
    """)
    conn.commit()
    conn.close()
    logger.info("Database setup complete.")

def create_user(user_id, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    try:
        cursor.execute("INSERT INTO users (user_id, hashed_password) VALUES (?, ?)", (user_id, hashed_password))
        conn.commit()
        logger.info(f"User '{user_id}' created.")
        return True
    except sqlite3.IntegrityError:
        print("That username already exists.")
        return False
    finally:
        conn.close()

def authenticate_user(user_id, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT hashed_password FROM users WHERE user_id = ?", (user_id,))
    result = cursor.fetchone()
    conn.close()
    if result and bcrypt.checkpw(password.encode('utf-8'), result["hashed_password"].encode('utf-8')):
        logger.info(f"User '{user_id}' authenticated.")
        return True
    return False

def user_exists(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE user_id = ?", (user_id,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

def load_messages_from_db(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role, content FROM messages WHERE user_id = ? ORDER BY timestamp ASC", (user_id,))
    history = [{"role": row["role"], "content": row["content"]} for row in cursor.fetchall()]
    conn.close()
    return history

def delete_all_user_messages(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM messages WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    logger.info(f"All messages deleted for user '{user_id}'.")

def save_message_to_db(user_id, session_id, role, content, sentiment, risk_level="N/A"):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO messages (user_id, session_id, role, content, sentiment_score, risk_level) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, session_id, role, content, sentiment, risk_level)
    )
    conn.commit()
    conn.close()

def classify_risk(score, reply):
    reply = reply.lower()
    if any(re.search(r'\b' + re.escape(w) + r'\b', reply) for w in ["suicide", "hopeless", "worthless", "kill myself", "end it all", "self-harm"]) or score < -0.6:
        return "High Risk"
    if score < -0.2 or "depression" in reply:
        return "Medium Risk"
    return "Low Risk"

def format_history_for_openrouter(history):
    formatted = [{"role": "system", "content": "You are a compassionate CBT-based mental health therapist. Respond with empathy, emotional validation, and open-ended questioning. Do not give hotlines unless suicidal ideation is explicitly stated."}]
    for entry in history[-MAX_CHAT_HISTORY_FOR_LLM:]:
        role = "user" if entry["role"] == "user" else "assistant"
        formatted.append({"role": role, "content": entry["content"]})
    return formatted

def get_ai_response(user_input, user_id, session_id):
    history = load_messages_from_db(user_id)
    sentiment = analyzer.polarity_scores(user_input)['compound']
    history.append({"role": "user", "content": user_input})
    messages = format_history_for_openrouter(history)
    reply = "I'm sorry, I'm having trouble connecting right now. Please try again later."
    risk = "Unknown"
    try:
        completion = client.chat.completions.create(
            model=OPENROUTER_MODEL,
            messages=messages,
            temperature=0.7,
            max_tokens=250,
            extra_headers={
                "HTTP-Referer": "https://your-app-domain.com",
                "X-Title": "MindEaseCLI-Basic"
            }
        )
        reply = completion.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"OpenRouter API Error: {e}")
    risk = classify_risk(sentiment, reply)
    save_message_to_db(user_id, session_id, "user", user_input, sentiment)
    save_message_to_db(user_id, session_id, "assistant", reply, analyzer.polarity_scores(reply)['compound'], risk)
    return reply, risk

def main():
    setup_database()
    print("\n🧠 Welcome to MindEase Therapist AI")
    print("✨ Your compassionate AI companion for mental wellness.\n")
    user_id = input("👤 Enter your username: ").strip()
    current_user_id = None
    if user_exists(user_id):
        print("🗂️ Previous session found.")
        pwd = input_password("🔑 Enter your existing password: ")
        if authenticate_user(user_id, pwd):
            current_user_id = user_id
            print("✅ Authenticated successfully.")
        else:
            print("❌ Incorrect password. Exiting.")
            return
    else:
        print("✨ New user. Let's create your account.")
        while True:
            pwd = input_password("🔐 Set a password for your account (min 6 characters): ")
            if len(pwd) < 6:
                print("⚠️ Password too short.")
                continue
            pwd2 = input_password("✅ Confirm password: ")
            if pwd == pwd2:
                if create_user(user_id, pwd):
                    current_user_id = user_id
                    print("✅ Account created successfully!")
                    break
                else:
                    user_id = input("😔 Try a different username: ").strip()
            else:
                print("🚫 Passwords did not match.")
    if current_user_id:
        old_messages = load_messages_from_db(current_user_id)
        if old_messages:
            choice = input("🧾 Do you want to continue your previous session? (yes(Y)/no(N)): ").strip().lower()
            if choice != "yes" or choice != "Y" :
                delete_choice = input("🗑️ Do you want to delete your previous session? (yes(Y)/no(N)): ").strip().lower()
                if delete_choice == "yes" or choice == "Y":
                    confirm_pwd = input_password("🔐 Re-enter your password to confirm deletion: ")
                    if authenticate_user(current_user_id, confirm_pwd):
                        delete_all_user_messages(current_user_id)
                        print("🗑️ Previous messages deleted.")
                    else:
                        print("❌ Password incorrect. Messages not deleted.")
        session_id = f"{current_user_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        print("\n🧘 Start your session. Type your messages below.")
        print(f"🛑 Type {', '.join(EXIT_COMMANDS)} to exit.\n")
        while True:
            user_input = input("You: ")
            if user_input.strip().lower() in EXIT_COMMANDS:
                print("👋 Ending session...")
                break
            response, risk = get_ai_response(user_input, current_user_id, session_id)
            print(f"\n🧠 MindEase ({risk}): {response}")
            if risk == "High Risk":
                print("\n🚨 High Alert")
            print()

if __name__ == "__main__":
    main()
