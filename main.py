
from utils.fetcher import fetch_paste
from utils.parser import extract_emails, extract_phone_numbers, extract_urls, extract_passwords, extract_usernames
from utils.writer import write_to_file

def run(url):
    dump = fetch_paste(url)
    if not dump:
        print("Failed to fetch paste.")
        return
    
    emails = extract_emails(dump)
    phone_numbers = extract_phone_numbers(dump)
    urls = extract_urls(dump)
    passwords = extract_passwords(dump)
    usernames = extract_usernames(dump)
    sensitive_data = {
        'emails': emails,
        'phone_numbers': phone_numbers,
        'urls': urls,
        'passwords': passwords,
        'usernames': usernames
    }
    write_to_file('emails.txt', emails)
    write_to_file('phone_numbers.txt', phone_numbers)
    write_to_file('urls.txt', urls)
    write_to_file('passwords.txt', passwords)
    write_to_file('usernames.txt', usernames)
    print("Data extraction complete. Files written successfully.")
0
if __name__ == "__main__":
    url = input('https://youtube.com')
    run(url)


