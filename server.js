
'use strict';

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const dotenv = require('dotenv');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const STORAGE_ROOT = process.env.STORAGE_ROOT || ROOT;
const DATA = path.join(STORAGE_ROOT, 'data');
const UP = path.join(STORAGE_ROOT, 'uploads');

app.set('trust proxy', 1);

for (const dir of [
  DATA,
  path.join(UP, 'profiles'),
  path.join(UP, 'schools')
]) {
  fs.mkdirSync(dir, { recursive: true });
}

/* =========================================================
   JSON STORAGE
   ========================================================= */

const files = {
  users: 'users.json',
  schools: 'schools.json',
  subjects: 'subjects.json',
  announcements: 'announcements.json',
  exams: 'exams.json',
  questions: 'questions.json',
  results: 'results.json',
  attempts: 'attempts.json',
  cheatEvents: 'cheat_events.json'
};

function read(key) {
  const filename = files[key];
  if (!filename) throw new Error(`Unknown data key: ${key}`);

  const file = path.join(DATA, filename);

  try {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(file, '[]', 'utf8');
      return [];
    }

    const text = fs.readFileSync(file, 'utf8');
    if (!text.trim()) return [];

    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    console.error(`READ ERROR [${key}]:`, error.message);
    return [];
  }
}

function write(key, value) {
  const filename = files[key];
  if (!filename) throw new Error(`Unknown data key: ${key}`);

  fs.mkdirSync(DATA, { recursive: true });

  const file = path.join(DATA, filename);
  const temp = `${file}.${process.pid}.tmp`;

  fs.writeFileSync(temp, JSON.stringify(value, null, 2), 'utf8');
  fs.renameSync(temp, file);
}

const uid = () => crypto.randomUUID();
const now = () => new Date().toISOString();

function safe(user) {
  if (!user) return null;

  return {
    id: user.id,
    fullName: user.fullName,
    username: user.username,
    email: user.email,
    role: user.role,
    schoolId: user.schoolId,
    profilePicture: user.profilePicture || '',
    active: user.active !== false,
    provider: user.provider || 'local',
    createdAt: user.createdAt
  };
}

function cleanText(value, max = 500) {
  return String(value ?? '').trim().slice(0, max);
}

function validColor(value) {
  return /^#[0-9a-f]{6}$/i.test(String(value || ''));
}

function schoolOf(id) {
  return read('schools').find(s => s.id === id) || null;
}

function userOf(id) {
  return read('users').find(u => u.id === id) || null;
}

function subjectOf(id) {
  return read('subjects').find(s => s.id === id) || null;
}

function examOf(id) {
  return read('exams').find(e => e.id === id) || null;
}

function questionsOf(examId) {
  return read('questions').filter(q => q.examId === examId);
}

function schoolScope(req, object) {
  return !!object && (
    req.user.role === 'superadmin' ||
    object.schoolId === req.user.schoolId
  );
}

function studentOwnsExam(req, exam) {
  return !!exam &&
    req.user.role === 'student' &&
    exam.schoolId === req.user.schoolId;
}

function redirectFor(user) {
  if (user.role === 'student') return '/student.html';
  if (user.role === 'teacher') return '/teacher.html';
  return '/admin.html';
}

/* =========================================================
   MIDDLEWARE / SESSION
   ========================================================= */

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const SESSION_SECRET = process.env.SESSION_SECRET;

if (process.env.NODE_ENV === 'production' && !SESSION_SECRET) {
  console.warn('WARNING: Set SESSION_SECRET in production.');
}

app.use(session({
  name: 'schoolhub.sid',
  secret: SESSION_SECRET || 'development-only-change-this-secret',
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.use(passport.initialize());
app.use(passport.session());

app.use('/uploads', express.static(UP));
app.use(express.static(path.join(ROOT, 'public')));

function auth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const user = userOf(req.session.userId);

  if (!user || user.active === false) {
    req.session.destroy(() => {});
    return res.status(401).json({ error: 'Account inactive' });
  }

  req.user = user;
  next();
}

function role(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Permission denied' });
    }
    next();
  };
}

/* =========================================================
   IMAGE UPLOADS
   ========================================================= */

function uploadFor(folder) {
  const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, path.join(UP, folder));
    },
    filename: (req, file, cb) => {
      cb(null, uid() + path.extname(file.originalname).toLowerCase());
    }
  });

  return multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
      const allowed = ['image/png', 'image/jpeg', 'image/webp'];
      if (!allowed.includes(file.mimetype)) {
        return cb(new Error('Only PNG, JPEG, and WebP images are allowed.'));
      }
      cb(null, true);
    }
  });
}

const profileUpload = uploadFor('profiles');
const logoUpload = uploadFor('schools');

/* =========================================================
   HEALTH / PLATFORM / CURRENT USER
   ========================================================= */

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    version: '4.0.0',
    storage: STORAGE_ROOT,
    features: [
      'multi-school',
      'school-isolation',
      'school-branding',
      'student-dashboard',
      'teacher-dashboard',
      'cbt',
      'server-timed-attempts',
      'anti-cheating-review-flags',
      'results',
      'question-bank',
      'announcements',
      'profile-pictures',
      'school-logos',
      'google-auth'
    ]
  });
});

app.get('/api/platform-config', (req, res) => {
  res.json({
    platformName: process.env.PLATFORM_NAME || 'SchoolHub Pro',
    platformDescription:
      process.env.PLATFORM_DESCRIPTION ||
      'Smart school management for modern schools.'
  });
});

app.get('/api/me', auth, (req, res) => {
  res.json({
    user: safe(req.user),
    school: req.user.schoolId ? schoolOf(req.user.schoolId) : null
  });
});

/* =========================================================
   REGISTER / LOGIN / LOGOUT
   ========================================================= */

app.post('/api/register', async (req, res) => {
  try {
    const schoolName = cleanText(req.body.schoolName, 150);
    const motto = cleanText(req.body.motto, 250);
    const fullName = cleanText(req.body.fullName, 150);
    const username = cleanText(req.body.username, 80);
    const email = cleanText(req.body.email, 180).toLowerCase();
    const password = String(req.body.password || '');

    if (!schoolName || !fullName || !username || !email || password.length < 8) {
      return res.status(400).json({
        error: 'Provide all required fields. Password must be at least 8 characters.'
      });
    }

    const users = read('users');
    const exists = users.some(u =>
      String(u.email || '').toLowerCase() === email ||
      String(u.username || '').toLowerCase() === username.toLowerCase()
    );

    if (exists) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }

    const school = {
      id: uid(),
      name: schoolName,
      motto,
      logo: '',
      primaryColor: '#2563eb',
      secondaryColor: '#16a34a',
      theme: 'light',
      active: true,
      createdAt: now()
    };

    const user = {
      id: uid(),
      fullName,
      username,
      email,
      passwordHash: await bcrypt.hash(password, 12),
      role: 'school_admin',
      schoolId: school.id,
      active: true,
      provider: 'local',
      createdAt: now()
    };

    const schools = read('schools');
    schools.push(school);
    write('schools', schools);

    users.push(user);
    write('users', users);

    req.session.userId = user.id;

    req.session.save(error => {
      if (error) {
        console.error('REGISTER SESSION ERROR:', error);
        return res.status(500).json({ error: 'Account created but session failed' });
      }

      res.json({
        ok: true,
        user: safe(user),
        school,
        redirect: '/admin.html'
      });
    });
  } catch (error) {
    console.error('REGISTER ERROR:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const identifier = cleanText(req.body.identifier, 180).toLowerCase();
    const password = String(req.body.password || '');

    if (!identifier || !password) {
      return res.status(400).json({ error: 'Username/email and password are required' });
    }

    const user = read('users').find(u =>
      (
        String(u.email || '').toLowerCase() === identifier ||
        String(u.username || '').toLowerCase() === identifier
      ) &&
      u.active !== false
    );

    if (!user || !user.passwordHash ||
        !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: 'Invalid login details' });
    }

    req.session.userId = user.id;

    req.session.save(error => {
      if (error) {
        console.error('LOGIN SESSION ERROR:', error);
        return res.status(500).json({ error: 'Could not save login session' });
      }

      res.json({
        ok: true,
        user: safe(user),
        redirect: redirectFor(user)
      });
    });
  } catch (error) {
    console.error('LOGIN ERROR:', error);
    res.status(500).json({ error: 'An internal error occurred during login' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(error => {
    if (error) return res.status(500).json({ error: 'Logout failed' });

    res.clearCookie('schoolhub.sid', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    });

    res.json({ ok: true });
  });
});

/* =========================================================
   SCHOOL BRANDING / LOGO / PROFILE
   ========================================================= */

app.put('/api/school/branding', auth, role('school_admin', 'superadmin'), (req, res) => {
  const schoolId = req.user.role === 'superadmin'
    ? cleanText(req.body.schoolId, 100)
    : req.user.schoolId;

  const schools = read('schools');
  const school = schools.find(s => s.id === schoolId);

  if (!school) return res.status(404).json({ error: 'School not found' });

  for (const key of ['name', 'motto']) {
    if (req.body[key] != null) school[key] = cleanText(req.body[key], 250);
  }

  for (const key of ['primaryColor', 'secondaryColor']) {
    if (req.body[key] != null) {
      if (!validColor(req.body[key])) {
        return res.status(400).json({ error: `Invalid ${key}` });
      }
      school[key] = req.body[key];
    }
  }

  if (req.body.theme != null) {
    if (!['light', 'dark'].includes(req.body.theme)) {
      return res.status(400).json({ error: 'Theme must be light or dark' });
    }
    school.theme = req.body.theme;
  }

  write('schools', schools);
  res.json({ ok: true, school });
});

app.post('/api/school/logo', auth, role('school_admin', 'superadmin'), logoUpload.single('logo'), (req, res) => {
  const schoolId = req.user.role === 'superadmin'
    ? cleanText(req.body.schoolId, 100)
    : req.user.schoolId;

  if (!req.file) return res.status(400).json({ error: 'Logo missing or invalid' });

  const schools = read('schools');
  const school = schools.find(s => s.id === schoolId);

  if (!school) return res.status(404).json({ error: 'School not found' });

  school.logo = '/uploads/schools/' + req.file.filename;
  write('schools', schools);

  res.json({ ok: true, school });
});

app.post('/api/profile-picture', auth, profileUpload.single('photo'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Image missing or invalid' });

  const users = read('users');
  const user = users.find(u => u.id === req.user.id);

  if (!user) return res.status(404).json({ error: 'User not found' });

  user.profilePicture = '/uploads/profiles/' + req.file.filename;
  write('users', users);

  res.json({ ok: true, user: safe(user) });
});

app.get('/api/school', auth, (req, res) => {
  res.json({ school: schoolOf(req.user.schoolId) });
});

/* =========================================================
   USER MANAGEMENT
   ========================================================= */

app.get('/api/users', auth, role('school_admin', 'superadmin'), (req, res) => {
  let users = read('users');

  if (req.user.role !== 'superadmin') {
    users = users.filter(u => u.schoolId === req.user.schoolId);
  }

  res.json(users.map(safe));
});

app.post('/api/users', auth, role('school_admin', 'superadmin'), async (req, res) => {
  try {
    const fullName = cleanText(req.body.fullName, 150);
    const username = cleanText(req.body.username, 80);
    const email = cleanText(req.body.email, 180).toLowerCase();
    const password = String(req.body.password || '');
    const requestedRole = req.body.role;

    if (!fullName || !username || !email || password.length < 8 ||
        !['teacher', 'student', 'school_admin'].includes(requestedRole)) {
      return res.status(400).json({ error: 'Invalid user data; password must be at least 8 characters' });
    }

    const users = read('users');

    if (users.some(u =>
      String(u.email || '').toLowerCase() === email ||
      String(u.username || '').toLowerCase() === username.toLowerCase()
    )) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }

    const schoolId = req.user.role === 'superadmin'
      ? cleanText(req.body.schoolId, 100)
      : req.user.schoolId;

    if (!schoolOf(schoolId)) {
      return res.status(400).json({ error: 'Valid schoolId required' });
    }

    const user = {
      id: uid(),
      fullName,
      username,
      email,
      passwordHash: await bcrypt.hash(password, 12),
      role: requestedRole,
      schoolId,
      active: true,
      provider: 'local',
      createdAt: now()
    };

    users.push(user);
    write('users', users);

    res.json({ ok: true, user: safe(user) });
  } catch (error) {
    console.error('CREATE USER ERROR:', error);
    res.status(500).json({ error: 'Could not create user' });
  }
});

app.put('/api/users/:id', auth, role('school_admin', 'superadmin'), async (req, res) => {
  try {
    const users = read('users');
    const user = users.find(u => u.id === req.params.id);

    if (!user || !schoolScope(req, user)) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.id === req.user.id && req.body.active === false) {
      return res.status(400).json({ error: 'You cannot deactivate your own account here' });
    }

    for (const key of ['fullName', 'username', 'email']) {
      if (req.body[key] != null) user[key] = cleanText(req.body[key], 180);
    }

    if (req.body.email != null) user.email = user.email.toLowerCase();

    if (req.body.active != null) user.active = req.body.active === true || req.body.active === 'true';

    if (req.body.role && ['teacher', 'student', 'school_admin'].includes(req.body.role)) {
      user.role = req.body.role;
    }

    if (req.body.password) {
      if (String(req.body.password).length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
      }
      user.passwordHash = await bcrypt.hash(String(req.body.password), 12);
    }

    write('users', users);
    res.json({ ok: true, user: safe(user) });
  } catch (error) {
    console.error('UPDATE USER ERROR:', error);
    res.status(500).json({ error: 'Could not update user' });
  }
});

app.delete('/api/users/:id', auth, role('school_admin', 'superadmin'), (req, res) => {
  let users = read('users');
  const user = users.find(u => u.id === req.params.id);

  if (!user || !schoolScope(req, user)) {
    return res.status(404).json({ error: 'User not found' });
  }

  if (user.id === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own account' });
  }

  users = users.filter(u => u.id !== user.id);
  write('users', users);

  res.json({ ok: true });
});

/* =========================================================
   DASHBOARD SUMMARIES
   ========================================================= */

app.get('/api/admin/summary', auth, role('school_admin', 'superadmin'), (req, res) => {
  const inScope = item => req.user.role === 'superadmin' || item.schoolId === req.user.schoolId;

  const users = read('users').filter(inScope);
  const schools = req.user.role === 'superadmin'
    ? read('schools')
    : read('schools').filter(s => s.id === req.user.schoolId);

  res.json({
    students: users.filter(u => u.role === 'student').length,
    teachers: users.filter(u => u.role === 'teacher').length,
    admins: users.filter(u => u.role === 'school_admin').length,
    schools: schools.length,
    subjects: read('subjects').filter(inScope).length,
    exams: read('exams').filter(inScope).length,
    results: read('results').filter(inScope).length
  });
});

app.get('/api/teacher/summary', auth, role('teacher', 'school_admin', 'superadmin'), (req, res) => {
  const inScope = item => req.user.role === 'superadmin' || item.schoolId === req.user.schoolId;
  const exams = read('exams').filter(inScope);
  const results = read('results').filter(inScope);
  const students = read('users').filter(u => inScope(u) && u.role === 'student');
  const subjects = read('subjects').filter(inScope);
  const examIds = new Set(exams.map(e => e.id));
  const questions = read('questions').filter(q => examIds.has(q.examId));

  const average = results.length
    ? Math.round(results.reduce((sum, r) => sum + Number(r.percentage || 0), 0) / results.length * 10) / 10
    : 0;

  res.json({
    subjects: subjects.length,
    exams: exams.length,
    published: exams.filter(e => e.status === 'published').length,
    students: students.length,
    submissions: results.length,
    average,
    questions: questions.length
  });
});

app.get('/api/student/summary', auth, role('student'), (req, res) => {
  const exams = read('exams').filter(e =>
    e.schoolId === req.user.schoolId && e.status === 'published'
  );

  const results = read('results').filter(r =>
    r.schoolId === req.user.schoolId && r.studentId === req.user.id
  );

  const completed = new Set(results.map(r => r.examId));

  const average = results.length
    ? Math.round(results.reduce((sum, r) => sum + Number(r.percentage || 0), 0) / results.length * 10) / 10
    : 0;

  res.json({
    available: exams.filter(e => !completed.has(e.id)).length,
    completed: results.length,
    average,
    totalExams: exams.length
  });
});

/* =========================================================
   SUBJECTS
   ========================================================= */

app.get('/api/subjects', auth, (req, res) => {
  res.json(read('subjects').filter(s => schoolScope(req, s)));
});

app.post('/api/subjects', auth, role('school_admin', 'teacher', 'superadmin'), (req, res) => {
  const schoolId = req.user.role === 'superadmin'
    ? cleanText(req.body.schoolId, 100)
    : req.user.schoolId;

  const name = cleanText(req.body.name, 150);
  if (!name || !schoolOf(schoolId)) {
    return res.status(400).json({ error: 'Name and valid school required' });
  }

  const subjects = read('subjects');
  const subject = {
    id: uid(),
    schoolId,
    name,
    code: cleanText(req.body.code, 30),
    description: cleanText(req.body.description, 500),
    createdBy: req.user.id,
    createdAt: now()
  };

  subjects.push(subject);
  write('subjects', subjects);
  res.json({ ok: true, subject });
});

app.put('/api/subjects/:id', auth, role('school_admin', 'teacher', 'superadmin'), (req, res) => {
  const subjects = read('subjects');
  const subject = subjects.find(s => s.id === req.params.id);

  if (!subject || !schoolScope(req, subject)) {
    return res.status(404).json({ error: 'Subject not found' });
  }

  for (const key of ['name', 'code', 'description']) {
    if (req.body[key] != null) subject[key] = cleanText(req.body[key], 500);
  }

  write('subjects', subjects);
  res.json({ ok: true, subject });
});

app.delete('/api/subjects/:id', auth, role('school_admin', 'superadmin'), (req, res) => {
  const subjects = read('subjects');
  const subject = subjects.find(s => s.id === req.params.id);

  if (!subject || !schoolScope(req, subject)) {
    return res.status(404).json({ error: 'Subject not found' });
  }

  write('subjects', subjects.filter(s => s.id !== subject.id));
  res.json({ ok: true });
});

/* =========================================================
   ANNOUNCEMENTS
   ========================================================= */

app.get('/api/announcements', auth, (req, res) => {
  const announcements = read('announcements')
    .filter(a => schoolScope(req, a))
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));

  res.json(announcements);
});

app.post('/api/announcements', auth, role('school_admin', 'teacher', 'superadmin'), (req, res) => {
  const schoolId = req.user.role === 'superadmin'
    ? cleanText(req.body.schoolId, 100)
    : req.user.schoolId;

  const title = cleanText(req.body.title, 180);
  const body = cleanText(req.body.body, 5000);

  if (!title || !body || !schoolOf(schoolId)) {
    return res.status(400).json({ error: 'Title, body, and valid school required' });
  }

  const announcements = read('announcements');
  const announcement = {
    id: uid(),
    schoolId,
    title,
    body,
    createdBy: req.user.id,
    createdAt: now()
  };

  announcements.push(announcement);
  write('announcements', announcements);
  res.json({ ok: true, announcement });
});

app.delete('/api/announcements/:id', auth, role('school_admin', 'superadmin'), (req, res) => {
  const announcements = read('announcements');
  const item = announcements.find(a => a.id === req.params.id);

  if (!item || !schoolScope(req, item)) {
    return res.status(404).json({ error: 'Announcement not found' });
  }

  write('announcements', announcements.filter(a => a.id !== item.id));
  res.json({ ok: true });
});

/* =========================================================
   EXAMS
   ========================================================= */

app.get('/api/exams', auth, (req, res) => {
  const results = read('results');

  const exams = read('exams')
    .filter(e => schoolScope(req, e))
    .filter(e => req.user.role !== 'student' || e.status === 'published');

  res.json(exams.map(e => ({
    ...e,
    subject: subjectOf(e.subjectId)?.name || 'Unknown subject',
    questionCount: questionsOf(e.id).length,
    submissionCount: results.filter(r => r.examId === e.id).length
  })));
});

app.get('/api/exams/:id', auth, (req, res) => {
  const exam = examOf(req.params.id);

  if (!exam || !schoolScope(req, exam)) {
    return res.status(404).json({ error: 'Exam not found' });
  }

  if (req.user.role === 'student') {
    return res.status(403).json({ error: 'Use the CBT take route' });
  }

  const questions = questionsOf(exam.id);

  res.json({
    ...exam,
    subject: subjectOf(exam.subjectId),
    questions,
    questionCount: questions.length,
    submissionCount: read('results').filter(r => r.examId === exam.id).length
  });
});

app.post('/api/exams', auth, role('school_admin', 'teacher', 'superadmin'), (req, res) => {
  const schoolId = req.user.role === 'superadmin'
    ? cleanText(req.body.schoolId, 100)
    : req.user.schoolId;

  const subject = read('subjects').find(s =>
    s.id === req.body.subjectId && s.schoolId === schoolId
  );

  const title = cleanText(req.body.title, 180);

  if (!subject || !title) {
    return res.status(400).json({ error: 'Valid subject and exam title required' });
  }

  const duration = Number(req.body.duration);
  if (!Number.isFinite(duration) || duration < 1 || duration > 600) {
    return res.status(400).json({ error: 'Duration must be between 1 and 600 minutes' });
  }

  const exam = {
    id: uid(),
    schoolId,
    subjectId: subject.id,
    title,
    duration: Math.floor(duration),
    instructions: cleanText(req.body.instructions, 5000),
    status: req.body.status === 'published' ? 'published' : 'draft',
    createdBy: req.user.id,
    createdAt: now()
  };

  const exams = read('exams');
  exams.push(exam);
  write('exams', exams);

  res.json({ ok: true, exam });
});

app.put('/api/exams/:id', auth, role('school_admin', 'teacher', 'superadmin'), (req, res) => {
  const exams = read('exams');
  const exam = exams.find(e => e.id === req.params.id);

  if (!exam || !schoolScope(req, exam)) {
    return res.status(404).json({ error: 'Exam not found' });
  }

  if (req.body.title != null) exam.title = cleanText(req.body.title, 180);
  if (req.body.instructions != null) exam.instructions = cleanText(req.body.instructions, 5000);

  if (req.body.status === 'draft' || req.body.status === 'published') {
    exam.status = req.body.status;
  }

  if (req.body.duration != null) {
    const duration = Number(req.body.duration);
    if (!Number.isFinite(duration) || duration < 1 || duration > 600) {
      return res.status(400).json({ error: 'Duration must be between 1 and 600 minutes' });
    }
    exam.duration = Math.floor(duration);
  }

  if (req.body.subjectId) {
    const subject = read('subjects').find(s =>
      s.id === req.body.subjectId && s.schoolId === exam.schoolId
    );

    if (!subject) return res.status(400).json({ error: 'Invalid subject' });
    exam.subjectId = subject.id;
  }

  write('exams', exams);
  res.json({ ok: true, exam });
});

app.delete('/api/exams/:id', auth, role('school_admin', 'teacher', 'superadmin'), (req, res) => {
  const exams = read('exams');
  const exam = exams.find(e => e.id === req.params.id);

  if (!exam || !schoolScope(req, exam)) {
    return res.status(404).json({ error: 'Exam not found' });
  }

  write('exams', exams.filter(e => e.id !== exam.id));
  write('questions', read('questions').filter(q => q.examId !== exam.id));
  write('results', read('results').filter(r => r.examId !== exam.id));
  write('attempts', read('attempts').filter(a => a.examId !== exam.id));
  write('cheatEvents', read('cheatEvents').filter(e => e.examId !== exam.id));

  res.json({ ok: true });
});

/* =========================================================
   QUESTION MANAGEMENT
   ========================================================= */

function validateQuestionInput(item) {
  if (!item || !cleanText(item.question, 5000) ||
      !Array.isArray(item.options) || item.options.length < 2 ||
      item.options.length > 10) {
    return 'Question and 2–10 options are required';
  }

  const answer = Number(item.answer);
  if (!Number.isInteger(answer) || answer < 0 || answer >= item.options.length) {
    return 'Invalid correct answer';
  }

  return null;
}

function makeQuestion(item, exam, userId) {
  return {
    id: uid(),
    examId: exam.id,
    schoolId: exam.schoolId,
    question: cleanText(item.question, 5000),
    options: item.options.map(o => cleanText(o, 1000)),
    answer: Number(item.answer),
    points: Math.max(1, Math.min(100, Number(item.points) || 1)),
    difficulty: cleanText(item.difficulty || 'medium', 30),
    explanation: cleanText(item.explanation, 2000),
    tags: cleanText(item.tags, 250),
    createdAt: now(),
    createdBy: userId
  };
}

app.post('/api/exams/:id/questions', auth, role('school_admin', 'teacher', 'superadmin'), (req, res) => {
  const exam = examOf(req.params.id);

  if (!exam || !schoolScope(req, exam)) {
    return res.status(404).json({ error: 'Exam not found' });
  }

  const error = validateQuestionInput(req.body);
  if (error) return res.status(400).json({ error });

  const questions = read('questions');
  const question = makeQuestion(req.body, exam, req.user.id);
  questions.push(question);
  write('questions', questions);

  res.json({ ok: true, question });
});

app.get('/api/exams/:id/questions', auth, role('school_admin', 'teacher', 'superadmin'), (req, res) => {
  const exam = examOf(req.params.id);

  if (!exam || !schoolScope(req, exam)) {
    return res.status(404).json({ error: 'Exam not found' });
  }

  res.json(questionsOf(exam.id));
});

app.put('/api/questions/:id', auth, role('school_admin', 'teacher', 'superadmin'), (req, res) => {
  const questions = read('questions');
  const question = questions.find(q => q.id === req.params.id);

  if (!question || !schoolScope(req, question)) {
    return res.status(404).json({ error: 'Question not found' });
  }

  const merged = { ...question, ...req.body };
  const error = validateQuestionInput(merged);
  if (error) return res.status(400).json({ error });

  question.question = cleanText(merged.question, 5000);
  question.options = merged.options.map(o => cleanText(o, 1000));
  question.answer = Number(merged.answer);
  question.points = Math.max(1, Math.min(100, Number(merged.points) || 1));
  question.difficulty = cleanText(merged.difficulty || 'medium', 30);
  question.explanation = cleanText(merged.explanation, 2000);
  question.tags = cleanText(merged.tags, 250);

  write('questions', questions);
  res.json({ ok: true, question });
});

app.delete('/api/questions/:id', auth, role('school_admin', 'teacher', 'superadmin'), (req, res) => {
  const questions = read('questions');
  const question = questions.find(q => q.id === req.params.id);

  if (!question || !schoolScope(req, question)) {
    return res.status(404).json({ error: 'Question not found' });
  }

  write('questions', questions.filter(q => q.id !== question.id));
  res.json({ ok: true });
});

app.get('/api/question-bank', auth, role('school_admin', 'teacher', 'superadmin'), (req, res) => {
  let questions = read('questions').filter(q => schoolScope(req, q));

  if (req.query.subjectId) {
    const examIds = new Set(read('exams')
      .filter(e => e.subjectId === req.query.subjectId && schoolScope(req, e))
      .map(e => e.id));

    questions = questions.filter(q => examIds.has(q.examId));
  }

  if (req.query.difficulty) {
    questions = questions.filter(q =>
      String(q.difficulty || '').toLowerCase() === String(req.query.difficulty).toLowerCase()
    );
  }

  if (req.query.tags) {
    const term = String(req.query.tags).toLowerCase();
    questions = questions.filter(q => String(q.tags || '').toLowerCase().includes(term));
  }

  if (req.query.search) {
    const term = String(req.query.search).toLowerCase();
    questions = questions.filter(q => String(q.question || '').toLowerCase().includes(term));
  }

  res.json(questions.map(q => ({
    ...q,
    exam: examOf(q.examId),
    subject: subjectOf(examOf(q.examId)?.subjectId)
  })));
});

app.post('/api/question-bank/bulk', auth, role('school_admin', 'teacher', 'superadmin'), (req, res) => {
  const { examId, questions: incoming } = req.body;

  if (!examId || !Array.isArray(incoming) || incoming.length > 1000) {
    return res.status(400).json({ error: 'Provide examId and up to 1000 questions' });
  }

  const exam = examOf(examId);
  if (!exam || !schoolScope(req, exam)) {
    return res.status(404).json({ error: 'Exam not found' });
  }

  const existing = read('questions');
  const created = [];

  for (const item of incoming) {
    if (validateQuestionInput(item)) continue;
    const question = makeQuestion(item, exam, req.user.id);
    existing.push(question);
    created.push(question);
  }

  write('questions', existing);
  res.json({ ok: true, created: created.length, questions: created });
});

/* =========================================================
   CBT ATTEMPTS + ACTIVITY FLAGS
   =========================================================
   Activity flags are review signals, not proof of misconduct.
   JSON file writes are not a transactional database. For high
   concurrency, move attempts/results to a transactional DB.
   ========================================================= */

function activeAttemptFor(examId, studentId) {
  return read('attempts').find(a =>
    a.examId === examId &&
    a.studentId === studentId &&
    a.status === 'in_progress'
  ) || null;
}

function resultFor(examId, studentId) {
  return read('results').find(r =>
    r.examId === examId && r.studentId === studentId
  ) || null;
}

function publicQuestion(question) {
  return {
    id: question.id,
    question: question.question,
    options: question.options,
    points: question.points,
    difficulty: question.difficulty,
    tags: question.tags
  };
}

function publicAttempt(attempt, exam) {
  return {
    id: attempt.id,
    examId: attempt.examId,
    startedAt: attempt.startedAt,
    deadlineAt: attempt.deadlineAt,
    status: attempt.status,
    exam: {
      id: exam.id,
      title: exam.title,
      duration: exam.duration,
      instructions: exam.instructions,
      subject: subjectOf(exam.subjectId)
    }
  };
}

function finalizeAttempt(attempt, exam, answers, automatic = false) {
  const attempts = read('attempts');
  const current = attempts.find(a => a.id === attempt.id);

  if (!current || current.status !== 'in_progress') {
    return { error: 'Attempt is not active' };
  }

  const existing = resultFor(exam.id, current.studentId);
  if (existing) {
    current.status = 'submitted';
    current.submittedAt = existing.submittedAt;
    write('attempts', attempts);
    return { result: existing };
  }

  const questions = questionsOf(exam.id);
  let score = 0;
  let total = 0;
  let correct = 0;
  const safeAnswers = {};

  for (const question of questions) {
    const points = Math.max(1, Number(question.points) || 1);
    total += points;

    const raw = answers && Object.prototype.hasOwnProperty.call(answers, question.id)
      ? answers[question.id]
      : undefined;

    const selected = Number(raw);
    const valid = Number.isInteger(selected) &&
      selected >= 0 &&
      selected < question.options.length;

    if (valid) safeAnswers[question.id] = selected;

    if (valid && selected === Number(question.answer)) {
      score += points;
      correct++;
    }
  }

  const percentage = total > 0
    ? Math.round(score / total * 10000) / 100
    : 0;

  const submittedAt = now();
  const result = {
    id: uid(),
    attemptId: current.id,
    examId: exam.id,
    schoolId: exam.schoolId,
    studentId: current.studentId,
    studentName: userOf(current.studentId)?.fullName || 'Student',
    examTitle: exam.title,
    score,
    total,
    correct,
    wrong: Math.max(0, questions.length - correct),
    percentage,
    answers: safeAnswers,
    submittedAt,
    autoSubmitted: automatic
  };

  const results = read('results');
  results.push(result);
  write('results', results);

  current.status = 'submitted';
  current.submittedAt = submittedAt;
  current.autoSubmitted = automatic;
  write('attempts', attempts);

  return { result };
}

app.post('/api/exams/:id/start', auth, role('student'), (req, res) => {
  const exam = examOf(req.params.id);

  if (!studentOwnsExam(req, exam)) {
    return res.status(404).json({ error: 'Exam not found' });
  }

  if (exam.status !== 'published') {
    return res.status(400).json({ error: 'This CBT is not published' });
  }

  if (!questionsOf(exam.id).length) {
    return res.status(400).json({ error: 'This CBT has no questions' });
  }

  const previousResult = resultFor(exam.id, req.user.id);
  if (previousResult) {
    return res.status(409).json({
      error: 'You have already submitted this CBT',
      result: previousResult
    });
  }

  let attempt = activeAttemptFor(exam.id, req.user.id);

  if (attempt && Date.now() > new Date(attempt.deadlineAt).getTime()) {
    const finalized = finalizeAttempt(attempt, exam, attempt.answers || {}, true);
    if (finalized.result) {
      return res.status(409).json({
        error: 'Your previous attempt has ended',
        result: finalized.result
      });
    }
    attempt = null;
  }

  if (!attempt) {
    const startedAt = Date.now();
    attempt = {
      id: uid(),
      examId: exam.id,
      schoolId: exam.schoolId,
      studentId: req.user.id,
      startedAt: new Date(startedAt).toISOString(),
      deadlineAt: new Date(startedAt + Math.max(1, Number(exam.duration) || 30) * 60000).toISOString(),
      status: 'in_progress',
      answers: {},
      createdAt: now()
    };

    const attempts = read('attempts');
    attempts.push(attempt);
    write('attempts', attempts);
  }

  const questions = questionsOf(exam.id).map(publicQuestion);

  res.json({
    ok: true,
    attempt: publicAttempt(attempt, exam),
    questions
  });
});

/* Compatibility route used by older student dashboard */
app.get('/api/exams/:id/take', auth, role('student'), (req, res) => {
  const exam = examOf(req.params.id);

  if (!studentOwnsExam(req, exam)) {
    return res.status(404).json({ error: 'Exam not found' });
  }

  if (exam.status !== 'published') {
    return res.status(400).json({ error: 'This CBT is not published' });
  }

  const previous = resultFor(exam.id, req.user.id);
  if (previous) {
    return res.status(409).json({
      error: 'You have already submitted this CBT',
      result: previous
    });
  }

  let attempt = activeAttemptFor(exam.id, req.user.id);

  if (!attempt) {
    const startedAt = Date.now();
    attempt = {
      id: uid(),
      examId: exam.id,
      schoolId: exam.schoolId,
      studentId: req.user.id,
      startedAt: new Date(startedAt).toISOString(),
      deadlineAt: new Date(startedAt + Math.max(1, Number(exam.duration) || 30) * 60000).toISOString(),
      status: 'in_progress',
      answers: {},
      createdAt: now()
    };

    const attempts = read('attempts');
    attempts.push(attempt);
    write('attempts', attempts);
  }

  res.json({
    attempt: publicAttempt(attempt, exam),
    exam: {
      id: exam.id,
      title: exam.title,
      duration: exam.duration,
      instructions: exam.instructions,
      subject: subjectOf(exam.subjectId)
    },
    questions: questionsOf(exam.id).map(publicQuestion)
  });
});

app.post('/api/exams/:id/activity', auth, role('student'), (req, res) => {
  const exam = examOf(req.params.id);

  if (!studentOwnsExam(req, exam)) {
    return res.status(404).json({ error: 'Exam not found' });
  }

  const attempt = activeAttemptFor(exam.id, req.user.id);

  if (!attempt) {
    return res.status(409).json({ error: 'No active attempt' });
  }

  if (Date.now() > new Date(attempt.deadlineAt).getTime()) {
    return res.status(409).json({ error: 'Attempt time has ended' });
  }

  const allowedTypes = new Set([
    'tab_hidden',
    'fullscreen_exit',
    'copy_attempt',
    'paste_attempt',
    'context_menu'
  ]);

  const type = cleanText(req.body.type, 50);

  if (!allowedTypes.has(type)) {
    return res.status(400).json({ error: 'Invalid activity type' });
  }

  const events = read('cheatEvents');
  const event = {
    id: uid(),
    attemptId: attempt.id,
    examId: exam.id,
    schoolId: exam.schoolId,
    studentId: req.user.id,
    type,
    recordedAt: now()
  };

  events.push(event);
  write('cheatEvents', events);

  res.json({ ok: true });
});

/* Save progress on the server; student cannot set their own timer. */
app.post('/api/exams/:id/save-progress', auth, role('student'), (req, res) => {
  const exam = examOf(req.params.id);

  if (!studentOwnsExam(req, exam)) {
    return res.status(404).json({ error: 'Exam not found' });
  }

  const attempts = read('attempts');
  const attempt = attempts.find(a =>
    a.examId === exam.id &&
    a.studentId === req.user.id &&
    a.status === 'in_progress'
  );

  if (!attempt) return res.status(409).json({ error: 'No active attempt' });

  if (Date.now() > new Date(attempt.deadlineAt).getTime()) {
    const finalized = finalizeAttempt(attempt, exam, attempt.answers || {}, true);
    return res.status(409).json({
      error: 'Time has ended',
      result: finalized.result || null
    });
  }

  const incoming = req.body.answers;
  if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) {
    return res.status(400).json({ error: 'Answers object required' });
  }

  const validQuestionIds = new Set(questionsOf(exam.id).map(q => q.id));
  const sanitized = {};

  for (const [questionId, value] of Object.entries(incoming)) {
    if (!validQuestionIds.has(questionId)) continue;
    const question = questionsOf(exam.id).find(q => q.id === questionId);
    const selected = Number(value);

    if (Number.isInteger(selected) && selected >= 0 && selected < question.options.length) {
      sanitized[questionId] = selected;
    }
  }

  attempt.answers = sanitized;
  attempt.lastSavedAt = now();
  write('attempts', attempts);

  res.json({
    ok: true,
    saved: Object.keys(sanitized).length,
    deadlineAt: attempt.deadlineAt
  });
});

app.post('/api/exams/:id/submit', auth, role('student'), (req, res) => {
  const exam = examOf(req.params.id);

  if (!studentOwnsExam(req, exam)) {
    return res.status(404).json({ error: 'Exam not found' });
  }

  const previous = resultFor(exam.id, req.user.id);
  if (previous) {
    return res.status(409).json({
      error: 'You have already submitted this CBT',
      result: previous
    });
  }

  const attempts = read('attempts');
  const attempt = attempts.find(a =>
    a.examId === exam.id &&
    a.studentId === req.user.id &&
    a.status === 'in_progress'
  );

  if (!attempt) {
    return res.status(409).json({ error: 'Start the CBT before submitting' });
  }

  const expired = Date.now() > new Date(attempt.deadlineAt).getTime();

  const submittedAnswers = req.body.answers &&
    typeof req.body.answers === 'object' &&
    !Array.isArray(req.body.answers)
      ? req.body.answers
      : attempt.answers || {};

  const finalized = finalizeAttempt(
    attempt,
    exam,
    submittedAnswers,
    expired
  );

  if (finalized.error) {
    return res.status(409).json({ error: finalized.error });
  }

  res.json({ ok: true, result: finalized.result });
});

/* =========================================================
   ANTI-CHEATING REVIEW API
   ========================================================= */

app.get('/api/exams/:id/activity', auth, role('school_admin', 'teacher', 'superadmin'), (req, res) => {
  const exam = examOf(req.params.id);

  if (!exam || !schoolScope(req, exam)) {
    return res.status(404).json({ error: 'Exam not found' });
  }

  const events = read('cheatEvents')
    .filter(e => e.examId === exam.id && schoolScope(req, e))
    .sort((a, b) => String(b.recordedAt).localeCompare(String(a.recordedAt)));

  res.json(events);
});

app.get('/api/exams/:id/attempts', auth, role('school_admin', 'teacher', 'superadmin'), (req, res) => {
  const exam = examOf(req.params.id);

  if (!exam || !schoolScope(req, exam)) {
    return res.status(404).json({ error: 'Exam not found' });
  }

  const attempts = read('attempts')
    .filter(a => a.examId === exam.id && schoolScope(req, a))
    .map(a => ({
      id: a.id,
      examId: a.examId,
      studentId: a.studentId,
      studentName: userOf(a.studentId)?.fullName || 'Student',
      startedAt: a.startedAt,
      deadlineAt: a.deadlineAt,
      submittedAt: a.submittedAt || null,
      status: a.status,
      autoSubmitted: a.autoSubmitted === true,
      activityCount: read('cheatEvents').filter(e => e.attemptId === a.id).length
    }));

  res.json(attempts);
});

/* =========================================================
   RESULTS
   ========================================================= */

app.get('/api/results', auth, (req, res) => {
  let results = read('results');

  if (req.user.role === 'student') {
    results = results.filter(r =>
      r.schoolId === req.user.schoolId &&
      r.studentId === req.user.id
    );
  } else if (req.user.role !== 'superadmin') {
    results = results.filter(r => r.schoolId === req.user.schoolId);
  }

  results.sort((a, b) => String(b.submittedAt).localeCompare(String(a.submittedAt)));
  res.json(results);
});

app.get('/api/results/:id', auth, (req, res) => {
  const result = read('results').find(r => r.id === req.params.id);

  if (!result) return res.status(404).json({ error: 'Result not found' });

  if (req.user.role === 'student' && result.studentId !== req.user.id) {
    return res.status(403).json({ error: 'Permission denied' });
  }

  if (req.user.role !== 'student' &&
      req.user.role !== 'superadmin' &&
      result.schoolId !== req.user.schoolId) {
    return res.status(403).json({ error: 'Permission denied' });
  }

  res.json({ result });
});

/* =========================================================
   SUPERADMIN
   ========================================================= */

app.get('/api/superadmin/schools', auth, role('superadmin'), (req, res) => {
  res.json(read('schools'));
});

app.post('/api/superadmin/schools', auth, role('superadmin'), (req, res) => {
  const name = cleanText(req.body.name, 150);
  if (!name) return res.status(400).json({ error: 'School name required' });

  const schools = read('schools');
  const school = {
    id: uid(),
    name,
    motto: cleanText(req.body.motto, 250),
    logo: '',
    primaryColor: validColor(req.body.primaryColor) ? req.body.primaryColor : '#2563eb',
    secondaryColor: validColor(req.body.secondaryColor) ? req.body.secondaryColor : '#16a34a',
    theme: ['light', 'dark'].includes(req.body.theme) ? req.body.theme : 'light',
    active: true,
    createdAt: now()
  };

  schools.push(school);
  write('schools', schools);
  res.json({ ok: true, school });
});

app.put('/api/superadmin/schools/:id', auth, role('superadmin'), (req, res) => {
  const schools = read('schools');
  const school = schools.find(s => s.id === req.params.id);

  if (!school) return res.status(404).json({ error: 'School not found' });

  for (const key of ['name', 'motto']) {
    if (req.body[key] != null) school[key] = cleanText(req.body[key], 250);
  }

  for (const key of ['primaryColor', 'secondaryColor']) {
    if (req.body[key] != null && validColor(req.body[key])) {
      school[key] = req.body[key];
    }
  }

  if (['light', 'dark'].includes(req.body.theme)) school.theme = req.body.theme;
  if (req.body.active != null) school.active = req.body.active === true || req.body.active === 'true';

  write('schools', schools);
  res.json({ ok: true, school });
});

app.get('/api/superadmin/all-users', auth, role('superadmin'), (req, res) => {
  res.json(read('users').map(safe));
});

/* =========================================================
   GOOGLE AUTH
   ========================================================= */

const googleConfigured = Boolean(
  process.env.GOOGLE_CLIENT_ID &&
  process.env.GOOGLE_CLIENT_SECRET &&
  process.env.GOOGLE_CALLBACK_URL
);

if (googleConfigured) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const users = read('users');
      const email = profile.emails?.[0]?.value?.toLowerCase();

      const user = users.find(u =>
        u.providerId === profile.id ||
        (email && String(u.email || '').toLowerCase() === email)
      );

      if (!user) {
        return done(null, false, {
          message: 'No SchoolHub account is linked to this Google account.'
        });
      }

      if (user.active === false) {
        return done(null, false, { message: 'This account is inactive.' });
      }

      user.provider = 'google';
      user.providerId = profile.id;

      if (!user.profilePicture && profile.photos?.[0]?.value) {
        user.profilePicture = profile.photos[0].value;
      }

      write('users', users);
      done(null, user);
    } catch (error) {
      done(error);
    }
  }));
}

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => done(null, userOf(id) || false));

app.get('/auth/google', (req, res, next) => {
  if (!googleConfigured) {
    return res.status(503).send('Google authentication is not configured.');
  }

  passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'select_account'
  })(req, res, next);
});

app.get('/auth/google/callback', (req, res, next) => {
  if (!googleConfigured) {
    return res.status(503).send('Google authentication is not configured.');
  }

  passport.authenticate('google', (error, user) => {
    if (error || !user) {
      console.error('GOOGLE LOGIN ERROR:', error || 'No matching user');
      return res.redirect('/login.html?error=google');
    }

    req.logIn(user, loginError => {
      if (loginError) {
        console.error('GOOGLE SESSION ERROR:', loginError);
        return res.redirect('/login.html?error=session');
      }

      req.session.userId = user.id;

      req.session.save(saveError => {
        if (saveError) {
          console.error('GOOGLE SESSION SAVE ERROR:', saveError);
          return res.redirect('/login.html?error=session');
        }

        res.redirect(redirectFor(user));
      });
    });
  })(req, res, next);
});

/* =========================================================
   ERRORS / FALLBACK
   ========================================================= */

app.use((error, req, res, next) => {
  console.error('REQUEST ERROR:', error);

  if (res.headersSent) return next(error);

  if (error instanceof multer.MulterError) {
    return res.status(400).json({ error: error.message });
  }

  res.status(500).json({
    error: process.env.NODE_ENV === 'production'
      ? 'An internal server error occurred'
      : error.message
  });
});

app.use('/api', (req, res) => {
  res.status(404).json({ error: 'API route not found' });
});

app.get('*', (req, res) => {
  const indexPath = path.join(ROOT, 'public', 'index.html');

  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);

  res.status(404).send('SchoolHub Pro frontend not found.');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('========================================');
  console.log('SchoolHub Pro server started');
  console.log(`Port: ${PORT}`);
  console.log(`Storage: ${STORAGE_ROOT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Google Auth: ${googleConfigured ? 'CONFIGURED' : 'NOT CONFIGURED'}`);
  console.log('========================================');
});

process.on('uncaughtException', error => {
  console.error('UNCAUGHT EXCEPTION:', error);
});

process.on('unhandledRejection', error => {
  console.error('UNHANDLED REJECTION:', error);
});
