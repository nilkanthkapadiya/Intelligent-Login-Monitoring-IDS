"""
================================================================================
Intelligent Login Attempt Monitoring and Intrusion Detection System (IDS)
Main Application Execution Entry Point
================================================================================
"""

import os
from app import create_app
from app.database.init_db import init_database

app = create_app(os.environ.get('FLASK_ENV', 'development'))

if __name__ == '__main__':
    print("[*] Launching Intelligent Login Attempt Monitoring & IDS System...")
    # Ensure DB schema and seeds exist on startup
    try:
        init_database()
    except Exception as e:
        print(f"[!] DB Initialization Notice: {str(e)}")

    print("[+] Server ready! Access web portal at: http://127.0.0.1:5000/")
    app.run(host='0.0.0.0', port=5000, debug=True)
