import re
def extract_emails(text):
    return re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)

def extract_phone_numbers(text):
    return re.findall(r'\b\d{10}\b|\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b', text)    

def extract_urls(text):
    return re.findall(r'(https?://[^\s]+)', text)

def extract_passwords(text):
    return re.findall(r'(?i)(?<!\w)(?:(?:(?:(?:(?:(?:(?:(?:(?:(?:(?:(?:[a-zA-Z0-9!@#$%^&*()_+={}\[\]:;"\'<>,.?/~`-]{8,})|(?:\bpassword\b))|(?:\bpass\b))|(?:\bpasswd\b))|(?:\bsecret\b))|(?:\bkey\b))|(?:\btoken\b))|(?:\bapi_key\b))|(?:\bapi_secret\b))', text)

def extract_usernames(text):
    return re.findall(r'\b[a-zA-Z0-9._-]{3,}\b', text)


def extract_sensitive_data(text):
    emails = extract_emails(text)
    phone_numbers = extract_phone_numbers(text)
    urls = extract_urls(text)
    
    return {
        'emails': emails,
        'phone_numbers': phone_numbers,
        'urls': urls
    }




