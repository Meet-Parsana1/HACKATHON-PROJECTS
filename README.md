# 🔐 Empathy Encryption Hackathon – Password Checker  

---

## 📖 Project Overview  
This project was built as part of the **Empathy Encryption Hackathon 2025**, where the challenge was revealed by **Dr. Kushal Shah** (Ex-IIT Delhi Professor, PhD IIT-Madras, AI Researcher & Educator).  

The goal was to design a **Password Checker Function in Python** that not only enforces security but also reflects *empathy for human users*.  

Unlike traditional validators that only check for rigid rules like *uppercase + number + symbol*, this solution goes deeper: it looks for **signs of human intentionality** and rejects **predictable or confusing patterns**.  

✅ **Built entirely with ChatGPT 🤖** as my coding partner.  

---

## ✨ Features  
- ✅ **Human-Centric Validation** → Rewards passwords that look natural, intentional, and human-created.  
- ❌ **Blocks Weak Choices** → Rejects trivial passwords (`password123`, `qwerty2024`, `11111111`).  
- 🚫 **Avoids Confusion** → Penalizes heavy use of visually similar characters (`O0`, `1lI`).  
- ⚖️ **Balanced Security** → Combines strength + usability (secure yet memorable).  
- 🧮 **Entropy-Aware** → Adds a gentle mathematical check for character variety.  
- 🔍 **Two-Layer Design** →  
  1. **Fatal rejects** (auto-block obvious weak patterns).  
  2. **Scoring system** (rewards good signals, penalizes bad ones).  

---

## 🛠️ Tech Stack  
- **Language**: Python 🐍  
- **Core Tools**:  
  - `re` → Regular expressions for pattern detection.  
  - `math` → Shannon entropy calculation.  
