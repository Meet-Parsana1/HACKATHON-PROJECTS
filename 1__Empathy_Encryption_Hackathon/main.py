"""
---------------------------------------------------------------------------
My Thought Process Behind This Solution:
---------------------------------------------------------------------------

When I read the problem statement, I understood that this Hackathon is not
just about making passwords "hard for machines", but also making them
"friendly for humans". That is why my solution is not a simple checklist like
"1 uppercase, 1 digit, 1 symbol". Instead, I tried to design a function that
thinks like a real product, not just like code.

1) First, I asked myself: what does an "empathetic password" look like?
    - It should not be too easy to guess (like 'password123' or 'qwerty').
    - It should not be confusing with characters that look the same (like 'O0O0').
    - It should look like something a human created with some care (like 'NovaTrail_19$elm').

2) Based on that, I built my logic in two layers:
    - Fatal Rejects: if a password is obviously weak or confusing, reject it immediately. Example: 'password123', '11111111', 'qwerty2024'.
    - Scoring System: for other passwords, I give points for good signals(like having word-like parts, mixing different character types, putting numbers in the middle) and subtract points for bad signals (like long sequences, repeated characters, confusing lookalikes).

3) I also used a small bit of math: Shannon entropy. This checks how much variety is in the password. But I only give it a small weight, because humans don’t make random strings—they make meaningful ones. So my focus stays on structure and intention, not pure randomness.

4) The final decision is simple: if the password score is good enough and it doesn’t trigger any fatal rule, I accept it. Otherwise, I reject it.

5) Why this is unique:
    - Many people will just write a regex like: must have uppercase + digit + symbol. That approach is rigid and predictable.
    - My approach rewards human creativity and intentionality, while still blocking lazy and common choices.
    - This matches the theme of the Hackathon: "Empathy Encryption"— security with empathy.

In short, my solution works like a guide, not a policeman. Instead of forcing
users into strict rules, it encourages natural, human-friendly, but still
secure passwords. That's why I believe this is a real-world solution, not just
a coding exercise.
"""

"""
Link of ChatGPT chat History for solving problem - https://chatgpt.com/share/68a04529-3a34-800c-a789-63ced9153ea2
"""

import re
# import re loads Python’s regular expressions (regex) module into our script.
# Regex is a powerful pattern matching tool that lets you search, validate, and manipulate text using rules.

import math
# import math loads Python’s math module, which contains mathematical functions and constants (like sqrt, log, pi, etc.). It gives access to operations that go beyond normal arithmetic (+, -, *, /).

# Required Main Function for password checking.
def is_valid_password(password: str) -> bool:
    """
    Product-aware password check for the 'Empathy Encryption Hackathon'.

    ------------------------------------------------------------------------
    Why this exists ?:
    ------------------------------------------------------------------------
    The Hackathon problem statement asked us to move beyond rigid "complexity
    checklists" (like "1 uppercase + 1 digit + 1 symbol") and instead design
    a password validation system that:
        - understands human intention behind password creation,
        - blocks trivial or dangerous patterns,
        - avoids confusing or unreadable strings,
        - balances creativity with security.

    So instead of treating passwords as raw strings, this function tries to
    interpret whether the *shape* of the string looks like something a real,
    thoughtful person would invent but which attackers would find less trivial.

    ------------------------------------------------------------------------
    Design notes (how this maps to the guiding principles):
    ------------------------------------------------------------------------
    1) Reasonably secure
        - Blocks "password123", "qwerty", "iloveyou", etc.
        - Detects long sequential runs like "abcdefg" or "123456".
        - Detects silly repetition like "abababab" or "11111111".

    2) Human intentionality
        - Rewards passwords that contain "word-like" chunks (something you can pronounce or that looks human, e.g. "mintChai", "River").
        - Rewards use of different character classes (letters, digits, symbols).
        - Rewards digits/symbols placed in the *middle* of words, not just appended lazily at the end.

    3) Avoid visual confusion
        - Penalizes passwords with too many lookalike characters: (0/O, 1/l/I, 5/S, 8/B, etc.).
        - Judges should be able to *read and share* the password clearly.

    4) Balanced variation
        - Limits repetition of single characters.
        - Discourages repeating substrings.

    5) Non-obvious human structure
        - "NovaTrail_19$elm" looks intentional and friendly.
        - "Password2024" looks predictable → reject.

    ------------------------------------------------------------------------
    How it works internally:
    - The function applies a set of "fatal reject" rules first (if triggered, no further scoring is needed).
    - Otherwise, it calculates a score based on signals (positive or negative).
    - Finally, if the score crosses a threshold (+3), the password is accepted.

    ------------------------------------------------------------------------
    Example accepted & rejected passwords (according to this logic):

    Accepted (intentional, friendly, varied):
        1) "mintChai#27Drift"
        2) "QuietLake_204"
        3) "Paper-Plane3!oak"
        4) "Granite*fox4River"
        5) "Sparrow7!maple"
        6) "NovaTrail_19$elm"
        7) "copperLeaf@82Walk"
        8) "nerdyCamel12!rope"
        9) "ByteGarden-31%wave"
        10) "Himalaya!leaf82"

    Rejected (predictable, weak, confusing):
        1) "password123"
        2) "qwerty2024"
        3) "asdfghjk"
        4) "11111111"
        5) "O0O0O0O0"
        6) "ABABABAB"
        7) "letmein"
        8) "iloveyou1"
        9) "admin2021"
        10) "user@123"

    ------------------------------------------------------------------------
    Real-world caveat:
    This is a "smart validator" based on principles. In production, it should
    be combined with breach-list checks (e.g., HaveIBeenPwned API) and
    rate-limiting, but those are outside this hackathon’s scope.
    """

    # -------------------------------
    # Guard rails: sanity checks first
    # -------------------------------
    if not isinstance(password, str):
        # Reject if input is not even a string
        return False

    # Clean leading/trailing control characters (like accidental copy-paste)
    s = password.strip("\n\r")

    # Enforce a minimum and maximum length.
    # Very short → trivially guessable.
    # Very long (128+) → likely copy-paste or junk data.
    if len(s) < 8:
        return False
    if len(s) > 128:
        return False

    # -------------------------------
    # Helper functions (small tools)
    # -------------------------------

    def shannon_entropy_per_char(text: str) -> float:
        """
        Shannon entropy is a way to measure randomness/variety.
        - Higher = more varied characters.
        - Too low = predictable.
        - Too high = might just be noise.
        We only use it as a small nudge, not the main driver.
        """
        if not text:
            return 0.0
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        H = 0.0
        for c in freq.values():
            p = c / len(text)
            H -= p * math.log2(p)
        return H  # bits per char

    def char_classes(text: str):
        """Check which types of characters are present (lower, upper, digit, symbol)."""
        has_lower = any("a" <= c <= "z" for c in text)
        has_upper = any("A" <= c <= "Z" for c in text)
        has_digit = any(c.isdigit() for c in text)
        has_symbol = any(not c.isalnum() and not c.isspace() for c in text)
        return has_lower, has_upper, has_digit, has_symbol

    def looks_like_sequence(text: str, min_run=4) -> bool:
        """Detect ascending/descending runs like 'abcd', '1234', 'ZYXW'."""
        if len(text) < min_run:
            return False
        runs = [
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789",
        ]
        for r in runs:
            if any(r[i : i + min_run] in text for i in range(len(r) - min_run + 1)):
                return True
            rev = r[::-1]
            if any(rev[i : i + min_run] in text for i in range(len(rev) - min_run + 1)):
                return True
        return False

    def has_keyboard_run(text: str, min_run=4) -> bool:
        """Detect runs along keyboard rows (qwerty, asdfgh, zxcvbn)."""
        rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
        t = text.lower()
        for row in rows:
            for i in range(len(row) - min_run + 1):
                seg = row[i : i + min_run]
                if seg in t or seg[::-1] in t:
                    return True
        return False

    def looks_like_word_segment(seg: str) -> bool:
        """
        A "word-ish" segment is something pronounceable:
        - at least 4 letters,
        - contains both vowels and consonants,
        - contains a consonant-vowel-consonant pattern.
        This signals human intent instead of random smash typing.
        """
        seg = re.sub(r"[^A-Za-z]", "", seg)
        if len(seg) < 4:
            return False
        has_vowel = re.search(r"[AEIOUaeiou]", seg) is not None
        has_cons = any(c.isalpha() and c.lower() not in "aeiou" for c in seg)
        sandwich = (
            re.search(
                r"[B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z][AEIOUaeiou][B-DF-HJ-NP-TV-Zb-df-hj-np-tv-z]",
                seg,
            )
            is not None
        )
        return has_vowel and has_cons and sandwich

    def wordish_presence(text: str) -> bool:
        """Check if the password contains at least one word-like segment or CamelCase."""
        for chunk in re.split(r"[\s\-_\.@#\$%!:\+\*]+", text):
            if looks_like_word_segment(chunk):
                return True
        if re.search(r"[A-Z][a-z]+[A-Z][a-z]*", text):  # CamelCase pattern
            return True
        return False

    def repeating_substring(text: str) -> bool:
        """Detects periodic repetition like 'ababab' or 'xyzxyz'."""
        n = len(text)
        for m in range(1, min(4, n)):  # small repeating units only
            if n % m == 0 and text == text[:m] * (n // m):
                return True
        return False

    def long_run_same_char(text: str, k=3) -> bool:
        """Reject if any character repeats more than k times in a row."""
        return re.search(r"(.)\1{" + str(k) + r",}", text) is not None

    def ambiguous_ratio(text: str) -> float:
        """
        Ratio of ambiguous/lookalike characters in the password.
        If it's too high, the password becomes unreadable/confusing.
        """
        groups = [
            set("0O"),
            set("1lI"),
            set("5S"),
            set("8B"),
            set("2Z"),
            set("6G"),
        ]
        amb = 0
        for ch in text:
            if any(ch in g for g in groups):
                amb += 1
        return amb / max(1, len(text))

    def non_edge_digit_symbol(text: str) -> bool:
        """
        Reward if digits/symbols appear *inside* words instead of only at edges.
        Example:
            'mintChai#27Drift' ✅
            'password123' ❌
        """
        return (
            re.search(r"[A-Za-z][0-9][A-Za-z]", text) is not None
            or re.search(r"[A-Za-z][^A-Za-z0-9][A-Za-z]", text) is not None
        )

    def has_year_like_suffix(text: str) -> bool:
        """Reject predictable year endings like '1999', '2024', etc."""
        return re.search(r"(19\d{2}|20[0-3]\d)$", text) is not None

    # -------------------------------
    # Fatal blocks (auto-reject rules)
    # -------------------------------
    lowered = s.lower()
    COMMON_BAD = {
        "password",
        "passw0rd",
        "qwerty",
        "asdfgh",
        "zxcvbn",
        "iloveyou",
        "welcome",
        "admin",
        "letmein",
        "login",
        "user",
        "guest",
        "abc123",
        "password1",
        "p@ssword",
        "dragon",
        "football",
    }
    if any(token in lowered for token in COMMON_BAD):
        return False
    if looks_like_sequence(s, min_run=5) or has_keyboard_run(s, min_run=5):
        return False
    if repeating_substring(s):
        return False
    if long_run_same_char(s, k=4):
        return False
    if ambiguous_ratio(s) > 0.55:
        return False

    # -------------------------------
    # Scoring system (soft checks)
    # -------------------------------
    score = 0

    # ✅ Length sweet spot: 10–64 → strong
    if 10 <= len(s) <= 64:
        score += 2
    elif 8 <= len(s) < 10:
        score += 1
    else:
        score += 0

    # ✅ Variety in character classes
    has_lower, has_upper, has_digit, has_symbol = char_classes(s)
    class_count = sum([has_lower, has_upper, has_digit, has_symbol])
    if class_count >= 3:
        score += 2
    elif class_count == 2:
        score += 1
    else:
        score -= 3

    # ✅ Word-ish presence = intentional
    if wordish_presence(s):
        score += 2

    # ✅ Digits/symbols in middle = intentional
    if non_edge_digit_symbol(s):
        score += 1

    # ❌ Obvious year suffix
    if has_year_like_suffix(s):
        score -= 2

    # ❌ Sequential/keyboard runs
    if looks_like_sequence(s, min_run=4):
        score -= 2
    if has_keyboard_run(s, min_run=4):
        score -= 2

    # ❌ Excessive repetition
    if long_run_same_char(s, k=3):
        score -= 2

    # ✅ Unique character ratio
    uniq_ratio = len(set(s)) / len(s)
    if uniq_ratio >= 0.5:
        score += 1
    elif uniq_ratio <= 0.3:
        score -= 1

    # ❌/✅ Ambiguity
    amb = ambiguous_ratio(s)
    if amb > 0.35:
        score -= 2
    elif amb > 0.15:
        score -= 1

    # ✅ Entropy bonus
    H = shannon_entropy_per_char(s)
    if len(s) >= 12 and H >= 2.5:
        score += 1

    # -------------------------------
    # Final decision
    # -------------------------------
    # Pass if score >= 3 AND no fatal rejects triggered.
    return score >= 3


if __name__ == "__main__":
    # Interactive mode for VS Code users
    password = input("\nEnter a password to check: ")

    if is_valid_password(password):
        print("\n✅ Accept: This password is valid.\n")
    else:
        print("\n❌ Reject: This password is invalid.\n")
