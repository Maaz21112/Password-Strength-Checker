# 🔒 Password Strength Checker  

![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue)  
![License](https://img.shields.io/badge/License-MIT-green)  

A Python-based tool to evaluate password security using **NIST guidelines** and **entropy analysis**, with breach detection via the HaveIBeenPwned API. Features a user-friendly GUI and actionable suggestions for stronger passwords.  

---

## 🚀 Features  
- **NIST SP 800-63B Compliance**  
  - Validates password length (8-64 chars) and blocks common passwords  
- **Entropy-Based Strength Grading**  
  - Calculates password randomness using Shannon entropy  
  - Strength levels: Very Weak → Very Strong  
- **Breach Detection**  
  - Uses HaveIBeenPwned API (k-anonymity model)  
- **GUI Interface**  
  - Real-time strength meter and color-coded feedback  
  - Password generator with customizable length/complexity  
  - Dark/light theme toggle  
- **CLI Support**  
  - Run checks directly from the terminal  

---

## 📥 Installation  
1. **Clone the repository**:  
   ```bash  
   git clone https://github.com/Maaz21112/password-strength-checker.git  
   cd password-strength-checker  
