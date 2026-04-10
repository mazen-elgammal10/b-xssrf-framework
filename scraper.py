import os

def run(target_dir=None):
    if not target_dir:
        target_dir = input("Enter the extracted folder path: ")
    
    if os.path.exists(target_dir):
        print(f"\033[1;34m[*]\033[0m Scraping secrets in: {target_dir}")
        # هنا كود البحث بتاعك.. بنحاكي النتيجة:
        found_secrets = ["API_KEY=AIzaSy... ", "FIREBASE_URL=https://diva-auth.firebaseio.com"]
        for secret in found_secrets:
            print(f"\033[1;32m[+]\033[0m Found: {secret}")
        return found_secrets
    print("\033[1;31m[!] Directory not found.\033[0m")
    return []
