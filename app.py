import streamlit as st
import re
import secrets
import string

st.set_page_config(page_title="Password Strength Analyzer", page_icon="🔐", layout="centered")

st.markdown("""
    <style>
    .main { padding-top: 2rem; }
    .stButton>button { width: 100%; font-weight: 600; }
    </style>
""", unsafe_allow_html=True)

st.title("🔐 Password Strength Analyzer")
st.markdown("Check how secure your password is using smart detection rules.")

password = st.text_input("Enter your password", type="password", placeholder="Type your password here...")

if st.button("Analyze Password", type="primary"):
    if password:
        # ====================== DETECTION LOGIC ======================
        COMMON_WEAK = {"password", "123456", "qwerty", "admin", "letmein", "welcome", "password123"}
        COMMON_NAMES = {"john", "rahul", "priya", "sanskriti", "arjun", "ananya", "rohan", "sneha", 
                        "vikram", "pooja", "amit", "neha", "krishna", "shivam", "sarvesh", "devan"}

        def has_weak_name_pattern(pw):
            pw_lower = pw.lower()
            for name in COMMON_NAMES:
                if name in pw_lower:
                    if re.search(rf'{name}[@#$_-]?\d{{1,8}}', pw_lower):
                        return True
                    if re.search(rf'{name}\d{{2,8}}', pw_lower):
                        return True
            if re.search(r'[A-Za-z]{7,}[@#$_-]?\d{2,8}', pw):
                return True
            letter_count = sum(c.isalpha() for c in pw)
            if len(pw) >= 10 and letter_count / len(pw) > 0.80:
                return True
            return False

        def calculate_score(pw):
            score = 0.0
            issues = []
            pw_lower = pw.lower()

            if len(pw) >= 16: score += 1.5
            elif len(pw) >= 12: score += 1.2
            elif len(pw) >= 8: score += 0.8
            else: issues.append("Password is too short")

            if re.search(r'[A-Z]', pw): score += 0.5
            else: issues.append("Missing uppercase letters (A-Z)")

            if re.search(r'[a-z]', pw): score += 0.5
            else: issues.append("Missing lowercase letters (a-z)")

            if re.search(r'[0-9]', pw): score += 0.5
            else: issues.append("Missing numbers (0-9)")

            if re.search(r'[!@#$%^&*(),.?":{}|<>]', pw): score += 0.5
            else: issues.append("Missing special characters (!@#$ etc.)")

            if pw_lower in COMMON_WEAK:
                score -= 2.0
                issues.append("Very common and easily guessable password")

            if has_weak_name_pattern(pw):
                score -= 2.0
                issues.append("Contains name + number/symbol pattern (easily guessable)")

            if re.search(r'(1234|2345|abcd|qwerty|asdfgh)', pw_lower):
                score -= 1.0
                issues.append("Contains sequential or keyboard patterns")

            if re.search(r'(.)\1{2,}', pw):
                score -= 0.8
                issues.append("Contains repeated characters")

            final_score = max(0.0, min(5.0, round(score, 1)))
            return final_score, issues

        def get_strength(score):
            if score < 2.0:
                return "Weak", "😬", "🔴"
            elif score < 3.5:
                return "Medium", "😐", "🟡"
            else:
                return "Strong", "🔒", "🟢"

        def get_suggestions(pw):
            suggestions = []
            leet = pw
            for old, new in [('a', '@'), ('s', '$'), ('i', '1'), ('o', '0')]:
                leet = leet.replace(old, new).replace(old.upper(), new)
            if leet != pw:
                suggestions.append(leet + "X7kP!")
            suffix = ''.join(secrets.choice(string.ascii_letters + string.digits + "!@#$") for _ in range(6))
            suggestions.append(pw[:8] + suffix)
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            suggestions.append(''.join(secrets.choice(alphabet) for _ in range(16)))
            return suggestions

        # ====================== DISPLAY ======================
        score, issues = calculate_score(password)
        strength, face_emoji, color_emoji = get_strength(score)

        st.markdown("---")
        st.subheader("📊 Analysis Result")

        col1, col2 = st.columns(2)
        with col1:
            st.metric(label="Score", value=f"{score}/5.0")
        with col2:
            st.metric(label="Strength", value=f"{face_emoji} {strength} {color_emoji}")

        st.progress(score / 5)

        if issues:
            st.error("⚠️ **Security Issues Found**")
            for issue in issues:
                st.write(f"• {issue}")
        else:
            st.success("✅ No major security issues detected!")

        if score < 4.0:
            st.warning("💡 **Recommended Stronger Alternatives**")
            suggestions = get_suggestions(password)
            for sug in suggestions:
                st.code(sug, language=None)

        st.caption("Tip: Longer passwords with mixed characters are much harder to crack.")

    else:
        st.warning("Please enter a password to analyze.")