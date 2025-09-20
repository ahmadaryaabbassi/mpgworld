# mpgepmcusers/validators.py
import re
from datetime import date

# Name rule:
# Each name-part must start with uppercase letter, followed by only lowercase letters.
# Accept single capital initial with optional dot (e.g. "A."), hyphenated or space-separated parts.
NAME_PART_RE = re.compile(r'^(?:[A-Z]\.|[A-Z][a-z]+)(?:[ -][A-Z][a-z]+)*$')

ALLOWED_EMAIL_DOMAINS = {'mpgepmc.com', 'gmail.com', 'yahoo.co'}

MOBILE_RE = re.compile(r'^\+(92|1)(?:303|333|456)\d{7}$')  # country + operator codes + 7 digits

def valid_name(value: str) -> bool:
    if not value:
        return False
    return bool(NAME_PART_RE.match(value.strip()))

def valid_email_domain(email: str) -> bool:
    try:
        domain = email.split('@', 1)[1].lower()
    except Exception:
        return False
    return domain in ALLOWED_EMAIL_DOMAINS

def valid_mobile(value: str) -> bool:
    return bool(MOBILE_RE.match(value.strip()))

def age_from_dob(dob):
    today = date.today()
    age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
    return age

def valid_age(dob):
    a = age_from_dob(dob)
    return 12 <= a <= 150

# password policy check: min8 max52, at least 1 digit 1 symbol 1 uppercase
import string
SYMBOLS = set(string.punctuation)

def valid_password(pw: str) -> (bool, str):
    if not (8 <= len(pw) <= 52):
        return False, "Password length must be between 8 and 52 characters."
    if not any(c.isdigit() for c in pw):
        return False, "Password must contain at least one digit."
    if not any(c.isupper() for c in pw):
        return False, "Password must contain at least one uppercase letter."
    if not any(c in SYMBOLS for c in pw):
        return False, "Password must contain at least one symbol (e.g. !@#$%)."
    return True, ""
