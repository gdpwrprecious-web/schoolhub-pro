# SchoolHub Pro V1

Professional multi-school school-management platform using Node.js, Express, sessions and JSON storage.

## Included
- Strict schoolId data isolation
- Superadmin + school admin + teacher + student roles
- School registration/login
- Optional Google OAuth
- School branding and logo
- Profile pictures
- User management
- Subjects
- Announcements
- CBT/exams
- Question bank
- Automatic marking
- Results
- Responsive dashboards

## Run
1. Extract this folder.
2. Open terminal in it.
3. `npm install`
4. Copy `.env.example` to `.env` and set SESSION_SECRET.
5. `npm start`
6. Open http://localhost:3000

Google OAuth is optional. If enabled, set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_CALLBACK_URL and register the callback URL in Google Cloud.
