from flask import Flask, request

app = Flask(__name__)

@app.route('/api/upload', methods=['POST'])
def mock_upload():
    # 1. التأكد من وجود التوكن (Authorization)
    auth_header = request.headers.get('Authorization')
    print(f"\n[\033[1;34m*\033[0m] Received Request with Auth: {auth_header}")

    # 2. التأكد من الملفات المرفوعة
    if 'file' in request.files:
        uploaded_file = request.files['file']
        content = uploaded_file.read().decode('utf-8', errors='ignore')
        
        print(f"[\033[1;32m+\033[0m] File Uploaded: {uploaded_file.filename}")
        print(f"[\033[1;33m!\033[0m] File Content (Potential Payload):\n{content[:200]}...")
        
        # محاكاة ثغرة SSRF (لو لقى رابط داخلي في الملف)
        if "http://127.0.0.1" in content:
            return f"SSRF Triggered! Accessing Internal Resource... [Admin Panel Content Here]", 200
            
        return "File processed successfully.", 200
    
    return "No file received.", 400

if __name__ == "__main__":
    print("[\033[1;32m+\033[0m] Vulnerable AI Server is running on http://127.0.0.1:5000")
    app.run(port=5000)
