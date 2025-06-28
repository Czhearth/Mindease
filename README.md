# 🧠 MindEase CLI — AI Therapist Chatbot

MindEase is a command-line based AI therapist chatbot designed to help users reflect on their thoughts using compassionate and CBT-based (Cognitive Behavioral Therapy) techniques.

> ⚠️ **This project is currently under development.**  
> Features and implementation may change as we iterate and improve.

---

## 📢 Disclaimer
MindEase is built to support self-reflection and basic wellness.
It is not designed for crisis intervention.
If you are in danger or experiencing a mental health emergency, please reach out to your local crisis hotline or emergency services.

---

## 💡 Features

- ✅ CLI-based AI therapy chatbot (no GUI)
- ✅ Powered by OpenRouter Gemini-2.5 Flash
- ✅ Sentiment analysis with VADER (NLTK)
- ✅ Risk level detection: Low / Medium / High
- ✅ Local message and user history via SQLite
- ✅ Secure user authentication (hashed passwords)
- ✅ Session continuation or deletion option
- ✅ Clean and simple UX

---

## 📁 Project Structure

``` lua
├── mindease.py
├── .env
├── requirements.txt
├── README.md
└── logs/
    ├── mindease.db 
    └── mindease.log
```

---

## 🛠️ Setup Instructions

### 1. Clone the repository:

```bash
git clone https://github.com/yourusername/MindEaseCLI.git
cd MindEaseCLI
```

### 2. Install dependencies:
```bash
pip install -r requirements.txt
```
Or install manually:

```bash
pip install openai python-dotenv nltk bcrypt
```

### 3. Create a .env file:
```env
OPENROUTER_API_KEY=your_openrouter_key_here
```
You can get your API key from https://openrouter.ai

---

## 🚀 Running the Chatbot
```bash
python mindease.py
```
Follow the terminal prompts to log in or register.

---

## 🔐 Security Notice
All data is stored locally, not on any server.<br>
Passwords are hashed using bcrypt.

---

## 🧑‍💻 Tech Stack
Python 3.11+<br>
OpenRouter API (Google Gemini-2.5 Flash)<br>
NLTK VADER Sentiment Analyzer<br>
SQLite3<br>
bcrypt (password hashing)<br>
dotenv (env handling)<br>

---

## 👨‍💻 Contributors
Siddharth<br>
Atharva<br>
Ninaad<br>
Arjun

