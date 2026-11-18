SUBMITTAL FORM & DRAWING CHECKER (WITH PRE-CREATED LOGIN)

HOW TO RUN:
1. Install Python 3.10 or newer.
2. Open a terminal inside the `backend` folder.
3. Create and activate a virtual environment (recommended):
   Windows:
     py -m venv .venv
     .venv\Scripts\activate
   Mac/Linux:
     python3 -m venv .venv
     source .venv/bin/activate
4. Install required packages:
     pip install -r requirements.txt
5. Start the server:
     uvicorn main:app --reload
6. Open your browser and go to:
     http://127.0.0.1:8000

DEFAULT PRE-CREATED LOGIN CREDENTIALS (NO SIGNUP):
- Super Admin:   Mobile: +971501111111  |  Password: admin123
- Company Admin: Mobile: +971502222222  |  Password: company123
- Employee:      Mobile: +971503333333  |  Password: emp123

FEATURES INCLUDED:
1. Closed-Access Login Page:
   - Only mobile numbers pre-added in the SQLite database (`users` table) can log in.
   - Super Admin has an "Admin User Management" tab to add new mobile numbers, assign passwords/roles, or deactivate users.
2. Submittal Form Checker:
   - Extracts Project Name, Submittal Number, Date, Contractor, Material Description, Manufacturer, Spec Reference, Revision, and Warranty from PDFs.
   - Checks duplicates and saves approved submittals to SQLite (`submissions` table).
3. Drawing Submittal Checker:
   - Extracts or allows manual entry of Project Name, Client, Contractor, Drawing Title, Drawing Number, Revision Number, Detail, Description, Legends, and Notes.
   - Checks duplicates and stores all drawing points in SQLite (`drawing_submissions` table).
