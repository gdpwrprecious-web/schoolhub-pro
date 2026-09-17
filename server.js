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

/*
|--------------------------------------------------------------------------
| RAILWAY / PROXY
|--------------------------------------------------------------------------
*/

app.set('trust proxy', 1);

/*
|--------------------------------------------------------------------------
| PERSISTENT STORAGE
|--------------------------------------------------------------------------
|
| Railway:
| STORAGE_ROOT=/app/storage
|
| Local:
| STORAGE_ROOT can be omitted and the project folder is used.
|
*/

const STORAGE_ROOT =
  process.env.STORAGE_ROOT ||
  ROOT;

const DATA = path.join(STORAGE_ROOT, 'data');
const UP = path.join(STORAGE_ROOT, 'uploads');

for (const directory of [
  DATA,
  path.join(UP, 'profiles'),
  path.join(UP, 'schools')
]) {
  fs.mkdirSync(directory, { recursive: true });
}

/*
|--------------------------------------------------------------------------
| DATA FILES
|--------------------------------------------------------------------------
*/

const files = {
  users: 'users.json',
  schools: 'schools.json',
  subjects: 'subjects.json',
  announcements: 'announcements.json',
  exams: 'exams.json',
  questions: 'questions.json',
  results: 'results.json'
};

/*
|--------------------------------------------------------------------------
| DATABASE HELPERS
|--------------------------------------------------------------------------
*/

const read = (key) => {
  const filePath = path.join(DATA, files[key]);

  try {
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, '[]');
      return [];
    }

    const content = fs.readFileSync(filePath, 'utf8');

    if (!content.trim()) {
      return [];
    }

    const parsed = JSON.parse(content);

    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    console.error(`READ ERROR [${key}]:`, error.message);
    return [];
  }
};

const write = (key, value) => {
  const filePath = path.join(DATA, files[key]);

  fs.mkdirSync(path.dirname(filePath), {
    recursive: true
  });

  fs.writeFileSync(
    filePath,
    JSON.stringify(value, null, 2),
    'utf8'
  );
};

const uid = () => crypto.randomUUID();

const now = () => new Date().toISOString();

/*
|--------------------------------------------------------------------------
| SAFE USER
|--------------------------------------------------------------------------
*/

const safe = (user) => {
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
};

/*
|--------------------------------------------------------------------------
| BODY PARSERS
|--------------------------------------------------------------------------
*/

app.use(express.json({
  limit: '10mb'
}));

app.use(express.urlencoded({
  extended: true,
  limit: '10mb'
}));

/*
|--------------------------------------------------------------------------
| SESSION
|--------------------------------------------------------------------------
*/

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  'change-this-secret-use-a-real-secret-in-production';

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

/*
|--------------------------------------------------------------------------
| PASSPORT
|--------------------------------------------------------------------------
*/

app.use(passport.initialize());
app.use(passport.session());

/*
|--------------------------------------------------------------------------
| STATIC FILES
|--------------------------------------------------------------------------
*/

app.use(
  '/uploads',
  express.static(UP)
);

app.use(
  express.static(
    path.join(ROOT, 'public')
  )
);

/*
|--------------------------------------------------------------------------
| AUTH HELPERS
|--------------------------------------------------------------------------
*/

function auth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: 'Authentication required'
    });
  }

  const user = read('users').find(
    (item) => item.id === req.session.userId
  );

  if (!user || user.active === false) {
    req.session.destroy(() => {});

    return res.status(401).json({
      error: 'Account inactive'
    });
  }

  req.user = user;

  next();
}

function role(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Permission denied'
      });
    }

    next();
  };
}

function schoolScope(req, object) {
  if (!object) return false;

  return (
    req.user.role === 'superadmin' ||
    object.schoolId === req.user.schoolId
  );
}

/*
|--------------------------------------------------------------------------
| UPLOADS
|--------------------------------------------------------------------------
*/

function uploadFor(folder) {
  const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(
        null,
        path.join(UP, folder)
      );
    },

    filename: (req, file, cb) => {
      cb(
        null,
        uid() +
          path
            .extname(file.originalname)
            .toLowerCase()
      );
    }
  });

  return multer({
    storage,

    limits: {
      fileSize: 5 * 1024 * 1024
    },

    fileFilter: (req, file, cb) => {
      const allowed = [
        'image/png',
        'image/jpeg',
        'image/webp'
      ];

      cb(
        null,
        allowed.includes(file.mimetype)
      );
    }
  });
}

const profileUpload = uploadFor('profiles');
const logoUpload = uploadFor('schools');

/*
|--------------------------------------------------------------------------
| LOOKUP HELPERS
|--------------------------------------------------------------------------
*/

const schoolOf = (id) =>
  read('schools').find(
    (school) => school.id === id
  ) || null;

const userOf = (id) =>
  read('users').find(
    (user) => user.id === id
  ) || null;

const subjectOf = (id) =>
  read('subjects').find(
    (subject) => subject.id === id
  ) || null;

const examOf = (id) =>
  read('exams').find(
    (exam) => exam.id === id
  ) || null;

const questionsOf = (examId) =>
  read('questions').filter(
    (question) => question.examId === examId
  );

/*
|--------------------------------------------------------------------------
| HEALTH
|--------------------------------------------------------------------------
*/

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    version: '3.2.0',
    storage: STORAGE_ROOT,

    features: [
      'multi-school',
      'school-isolation',
      'school-branding',
      'teacher-dashboard',
      'student-dashboard',
      'cbt-arena',
      'results',
      'question-bank',
      'announcements',
      'profile-pictures',
      'school-logos',
      'railway-persistent-storage',
      'google-auth'
    ]
  });
});

/*
|--------------------------------------------------------------------------
| PLATFORM CONFIG
|--------------------------------------------------------------------------
*/

app.get('/api/platform-config', (req, res) => {
  res.json({
    platformName:
      process.env.PLATFORM_NAME ||
      'SchoolHub Pro',

    platformDescription:
      process.env.PLATFORM_DESCRIPTION ||
      'Smart school management for modern schools.'
  });
});

/*
|--------------------------------------------------------------------------
| CURRENT USER
|--------------------------------------------------------------------------
*/

app.get('/api/me', auth, (req, res) => {
  res.json({
    user: safe(req.user),

    school: req.user.schoolId
      ? schoolOf(req.user.schoolId)
      : null
  });
});

/*
|--------------------------------------------------------------------------
| REGISTER SCHOOL
|--------------------------------------------------------------------------
*/

app.post('/api/register', async (req, res) => {
  try {
    const {
      schoolName,
      motto,
      fullName,
      username,
      email,
      password
    } = req.body;

    if (
      !schoolName ||
      !fullName ||
      !username ||
      !email ||
      !password
    ) {
      return res.status(400).json({
        error:
          'All required fields must be supplied'
      });
    }

    let users = read('users');

    const normalizedEmail =
      String(email)
        .trim()
        .toLowerCase();

    const normalizedUsername =
      String(username).trim();

    const exists = users.some(
      (user) =>
        user.email?.toLowerCase() ===
          normalizedEmail ||
        user.username?.toLowerCase() ===
          normalizedUsername.toLowerCase()
    );

    if (exists) {
      return res.status(409).json({
        error:
          'Username or email already exists'
      });
    }

    let schools = read('schools');

    const school = {
      id: uid(),
      name: String(schoolName).trim(),
      motto: String(motto || '').trim(),
      logo: '',
      primaryColor: '#2563eb',
      secondaryColor: '#16a34a',
      theme: 'light',
      active: true,
      createdAt: now()
    };

    schools.push(school);

    write('schools', schools);

    const user = {
      id: uid(),
      fullName: String(fullName).trim(),
      username: normalizedUsername,
      email: normalizedEmail,
      passwordHash:
        await bcrypt.hash(password, 10),
      role: 'school_admin',
      schoolId: school.id,
      active: true,
      provider: 'local',
      createdAt: now()
    };

    users.push(user);

    write('users', users);

    req.session.userId = user.id;

    req.session.save((error) => {
      if (error) {
        console.error(
          'REGISTER SESSION ERROR:',
          error
        );

        return res.status(500).json({
          error:
            'Account created but session could not be started'
        });
      }

      res.json({
        ok: true,
        user: safe(user),
        school,
        redirect: '/admin.html'
      });
    });
  } catch (error) {
    console.error(
      'REGISTER ERROR:',
      error
    );

    res.status(500).json({
      error: 'Registration failed'
    });
  }
});

/*
|--------------------------------------------------------------------------
| NORMAL LOGIN
|--------------------------------------------------------------------------
*/

app.post('/api/login', async (req, res) => {
  try {
    const identifier =
      String(
        req.body.identifier || ''
      ).trim();

    const password =
      String(
        req.body.password || ''
      );

    if (!identifier || !password) {
      return res.status(400).json({
        error:
          'Username/email and password are required'
      });
    }

    const normalized =
      identifier.toLowerCase();

    const user = read('users').find(
      (item) =>
        (
          item.email?.toLowerCase() ===
            normalized ||
          item.username?.toLowerCase() ===
            normalized
        ) &&
        item.active !== false
    );

    if (
      !user ||
      !user.passwordHash ||
      !(await bcrypt.compare(
        password,
        user.passwordHash
      ))
    ) {
      return res.status(401).json({
        error: 'Invalid login details'
      });
    }

    req.session.userId = user.id;

    req.session.save((error) => {
      if (error) {
        console.error(
          'LOGIN SESSION SAVE ERROR:',
          error
        );

        return res.status(500).json({
          error:
            'Login successful, but session could not be saved'
        });
      }

      let redirect = '/admin.html';

      if (user.role === 'student') {
        redirect = '/student.html';
      }

      if (user.role === 'teacher') {
        redirect = '/teacher.html';
      }

      if (
        user.role === 'school_admin' ||
        user.role === 'superadmin'
      ) {
        redirect = '/admin.html';
      }

      res.json({
        ok: true,
        user: safe(user),
        redirect
      });
    });
  } catch (error) {
    console.error(
      'LOGIN ERROR:',
      error
    );

    res.status(500).json({
      error:
        'An internal error occurred during login'
    });
  }
});

/*
|--------------------------------------------------------------------------
| LOGOUT
|--------------------------------------------------------------------------
*/

app.post('/api/logout', (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        error: 'Logout failed'
      });
    }

    res.clearCookie('connect.sid', {
      httpOnly: true,
      secure:
        process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    });

    res.json({
      ok: true
    });
  });
});

/*
|--------------------------------------------------------------------------
| SCHOOL BRANDING
|--------------------------------------------------------------------------
*/

app.put(
  '/api/school/branding',
  auth,
  role('school_admin', 'superadmin'),
  (req, res) => {
    const schoolId =
      req.user.role === 'superadmin'
        ? req.body.schoolId
        : req.user.schoolId;

    let schools = read('schools');

    const school = schools.find(
      (item) => item.id === schoolId
    );

    if (!school) {
      return res.status(404).json({
        error: 'School not found'
      });
    }

    const allowed = [
      'name',
      'motto',
      'primaryColor',
      'secondaryColor',
      'theme'
    ];

    for (const key of allowed) {
      if (req.body[key] != null) {
        school[key] =
          String(req.body[key]);
      }
    }

    write('schools', schools);

    res.json({
      ok: true,
      school
    });
  }
);

/*
|--------------------------------------------------------------------------
| SCHOOL LOGO
|--------------------------------------------------------------------------
*/

app.post(
  '/api/school/logo',
  auth,
  role('school_admin', 'superadmin'),
  logoUpload.single('logo'),
  (req, res) => {
    const schoolId =
      req.user.role === 'superadmin'
        ? req.body.schoolId
        : req.user.schoolId;

    if (!req.file) {
      return res.status(400).json({
        error: 'Logo missing'
      });
    }

    let schools = read('schools');

    const school = schools.find(
      (item) => item.id === schoolId
    );

    if (!school) {
      return res.status(404).json({
        error: 'School not found'
      });
    }

    school.logo =
      '/uploads/schools/' +
      req.file.filename;

    write('schools', schools);

    res.json({
      ok: true,
      school
    });
  }
);

/*
|--------------------------------------------------------------------------
| PROFILE PICTURE
|--------------------------------------------------------------------------
*/

app.post(
  '/api/profile-picture',
  auth,
  profileUpload.single('photo'),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        error: 'Image missing'
      });
    }

    let users = read('users');

    const user = users.find(
      (item) => item.id === req.user.id
    );

    if (!user) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    user.profilePicture =
      '/uploads/profiles/' +
      req.file.filename;

    write('users', users);

    res.json({
      ok: true,
      user: safe(user)
    });
  }
);

/*
|--------------------------------------------------------------------------
| SCHOOL
|--------------------------------------------------------------------------
*/

app.get('/api/school', auth, (req, res) => {
  res.json({
    school: schoolOf(
      req.user.schoolId
    )
  });
});

/*
|--------------------------------------------------------------------------
| USERS
|--------------------------------------------------------------------------
*/

app.get(
  '/api/users',
  auth,
  role('school_admin', 'superadmin'),
  (req, res) => {
    let users = read('users');

    if (req.user.role !== 'superadmin') {
      users = users.filter(
        (user) =>
          user.schoolId ===
          req.user.schoolId
      );
    }

    res.json(
      users.map(safe)
    );
  }
);

app.post(
  '/api/users',
  auth,
  role('school_admin', 'superadmin'),
  async (req, res) => {
    try {
      const {
        fullName,
        username,
        email,
        password,
        role: requestedRole
      } = req.body;

      const allowedRoles = [
        'teacher',
        'student',
        'school_admin'
      ];

      if (
        !fullName ||
        !username ||
        !email ||
        !password ||
        !allowedRoles.includes(
          requestedRole
        )
      ) {
        return res.status(400).json({
          error: 'Invalid user data'
        });
      }

      let users = read('users');

      const normalizedEmail =
        String(email)
          .trim()
          .toLowerCase();

      const normalizedUsername =
        String(username).trim();

      const exists = users.some(
        (user) =>
          user.email?.toLowerCase() ===
            normalizedEmail ||
          user.username?.toLowerCase() ===
            normalizedUsername.toLowerCase()
      );

      if (exists) {
        return res.status(409).json({
          error: 'User exists'
        });
      }

      const schoolId =
        req.user.role === 'superadmin'
          ? req.body.schoolId
          : req.user.schoolId;

      if (!schoolId) {
        return res.status(400).json({
          error: 'schoolId required'
        });
      }

      if (!schoolOf(schoolId)) {
        return res.status(400).json({
          error: 'School not found'
        });
      }

      const user = {
        id: uid(),
        fullName:
          String(fullName).trim(),
        username: normalizedUsername,
        email: normalizedEmail,
        passwordHash:
          await bcrypt.hash(
            password,
            10
          ),
        role: requestedRole,
        schoolId,
        active: true,
        provider: 'local',
        createdAt: now()
      };

      users.push(user);

      write('users', users);

      res.json({
        ok: true,
        user: safe(user)
      });
    } catch (error) {
      console.error(
        'CREATE USER ERROR:',
        error
      );

      res.status(500).json({
        error: 'Could not create user'
      });
    }
  }
);

app.put(
  '/api/users/:id',
  auth,
  role('school_admin', 'superadmin'),
  async (req, res) => {
    try {
      let users = read('users');

      const user = users.find(
        (item) =>
          item.id === req.params.id
      );

      if (
        !user ||
        !schoolScope(req, user)
      ) {
        return res.status(404).json({
          error: 'User not found'
        });
      }

      for (const key of [
        'fullName',
        'username',
        'email',
        'active'
      ]) {
        if (req.body[key] != null) {
          user[key] = req.body[key];
        }
      }

      const allowedRoles = [
        'teacher',
        'student',
        'school_admin'
      ];

      if (
        req.body.role &&
        allowedRoles.includes(
          req.body.role
        )
      ) {
        user.role = req.body.role;
      }

      if (req.body.password) {
        user.passwordHash =
          await bcrypt.hash(
            req.body.password,
            10
          );
      }

      write('users', users);

      res.json({
        ok: true,
        user: safe(user)
      });
    } catch (error) {
      console.error(
        'UPDATE USER ERROR:',
        error
      );

      res.status(500).json({
        error: 'Could not update user'
      });
    }
  }
);

app.delete(
  '/api/users/:id',
  auth,
  role('school_admin', 'superadmin'),
  (req, res) => {
    let users = read('users');

    const user = users.find(
      (item) =>
        item.id === req.params.id
    );

    if (
      !user ||
      !schoolScope(req, user)
    ) {
      return res.status(404).json({
        error: 'User not found'
      });
    }

    users = users.filter(
      (item) =>
        item.id !== user.id
    );

    write('users', users);

    res.json({
      ok: true
    });
  }
);

/*
|--------------------------------------------------------------------------
| ADMIN SUMMARY
|--------------------------------------------------------------------------
*/

app.get(
  '/api/admin/summary',
  auth,
  role('school_admin', 'superadmin'),
  (req, res) => {
    const users =
      req.user.role === 'superadmin'
        ? read('users')
        : read('users').filter(
            (user) =>
              user.schoolId ===
              req.user.schoolId
          );

    const schools =
      req.user.role === 'superadmin'
        ? read('schools')
        : read('schools').filter(
            (school) =>
              school.id ===
              req.user.schoolId
          );

    const subjects =
      read('subjects').filter(
        (item) =>
          req.user.role ===
            'superadmin' ||
          item.schoolId ===
            req.user.schoolId
      );

    const exams =
      read('exams').filter(
        (item) =>
          req.user.role ===
            'superadmin' ||
          item.schoolId ===
            req.user.schoolId
      );

    const results =
      read('results').filter(
        (item) =>
          req.user.role ===
            'superadmin' ||
          item.schoolId ===
            req.user.schoolId
      );

    res.json({
      students:
        users.filter(
          (user) =>
            user.role === 'student'
        ).length,

      teachers:
        users.filter(
          (user) =>
            user.role === 'teacher'
        ).length,

      admins:
        users.filter(
          (user) =>
            user.role === 'school_admin'
        ).length,

      schools: schools.length,

      subjects: subjects.length,

      exams: exams.length,

      results: results.length
    });
  }
);

/*
|--------------------------------------------------------------------------
| TEACHER SUMMARY
|--------------------------------------------------------------------------
*/

app.get(
  '/api/teacher/summary',
  auth,
  role(
    'teacher',
    'school_admin',
    'superadmin'
  ),
  (req, res) => {
    let exams = [];
    let results = [];
    let students = [];
    let subjects = [];

    if (
      req.user.role ===
      'superadmin'
    ) {
      exams = read('exams');
      results = read('results');

      students =
        read('users').filter(
          (user) =>
            user.role === 'student'
        );

      subjects = read('subjects');
    } else {
      const schoolId =
        req.user.schoolId;

      exams =
        read('exams').filter(
          (exam) =>
            exam.schoolId === schoolId
        );

      results =
        read('results').filter(
          (result) =>
            result.schoolId ===
            schoolId
        );

      students =
        read('users').filter(
          (user) =>
            user.schoolId ===
              schoolId &&
            user.role === 'student'
        );

      subjects =
        read('subjects').filter(
          (subject) =>
            subject.schoolId ===
            schoolId
        );
    }

    const published =
      exams.filter(
        (exam) =>
          exam.status ===
          'published'
      );

    const average =
      results.length
        ? Math.round(
            (
              results.reduce(
                (total, result) =>
                  total +
                  Number(
                    result.percentage ||
                      0
                  ),
                0
              ) /
              results.length
            ) * 10
          ) / 10
        : 0;

    const examIds = new Set(
      exams.map(
        (exam) => exam.id
      )
    );

    const questions =
      read('questions').filter(
        (question) =>
          examIds.has(
            question.examId
          )
      );

    res.json({
      subjects: subjects.length,
      exams: exams.length,
      published: published.length,
      students: students.length,
      submissions: results.length,
      average,
      questions: questions.length
    });
  }
);

/*
|--------------------------------------------------------------------------
| STUDENT SUMMARY
|--------------------------------------------------------------------------
*/

app.get(
  '/api/student/summary',
  auth,
  role('student'),
  (req, res) => {
    const exams =
      read('exams').filter(
        (exam) =>
          exam.schoolId ===
            req.user.schoolId &&
          exam.status ===
            'published'
      );

    const results =
      read('results').filter(
        (result) =>
          result.schoolId ===
            req.user.schoolId &&
          result.studentId ===
            req.user.id
      );

    const completed =
      new Set(
        results.map(
          (result) =>
            result.examId
        )
      );

    const average =
      results.length
        ? Math.round(
            (
              results.reduce(
                (total, result) =>
                  total +
                  Number(
                    result.percentage ||
                      0
                  ),
                0
              ) /
              results.length
            ) * 10
          ) / 10
        : 0;

    res.json({
      available:
        exams.filter(
          (exam) =>
            !completed.has(
              exam.id
            )
        ).length,

      completed:
        results.length,

      average,

      totalExams:
        exams.length
    });
  }
);

/*
|--------------------------------------------------------------------------
| SUBJECTS
|--------------------------------------------------------------------------
*/

app.get(
  '/api/subjects',
  auth,
  (req, res) => {
    res.json(
      read('subjects').filter(
        (subject) =>
          schoolScope(
            req,
            subject
          )
      )
    );
  }
);

app.post(
  '/api/subjects',
  auth,
  role(
    'school_admin',
    'teacher',
    'superadmin'
  ),
  (req, res) => {
    const schoolId =
      req.user.role ===
      'superadmin'
        ? req.body.schoolId
        : req.user.schoolId;

    if (
      !schoolId ||
      !req.body.name
    ) {
      return res.status(400).json({
        error:
          'Name and school required'
      });
    }

    if (!schoolOf(schoolId)) {
      return res.status(400).json({
        error: 'School not found'
      });
    }

    let subjects =
      read('subjects');

    const subject = {
      id: uid(),
      schoolId,
      name:
        String(
          req.body.name
        ).trim(),

      code:
        String(
          req.body.code || ''
        ).trim(),

      description:
        String(
          req.body.description ||
            ''
        ).trim(),

      createdBy:
        req.user.id,

      createdAt: now()
    };

    subjects.push(subject);

    write(
      'subjects',
      subjects
    );

    res.json({
      ok: true,
      subject
    });
  }
);

app.put(
  '/api/subjects/:id',
  auth,
  role(
    'school_admin',
    'teacher',
    'superadmin'
  ),
  (req, res) => {
    let subjects =
      read('subjects');

    const subject =
      subjects.find(
        (item) =>
          item.id ===
          req.params.id
      );

    if (
      !subject ||
      !schoolScope(
        req,
        subject
      )
    ) {
      return res.status(404).json({
        error: 'Subject not found'
      });
    }

    if (req.body.name != null) {
      subject.name =
        String(
          req.body.name
        ).trim();
    }

    if (req.body.code != null) {
      subject.code =
        String(
          req.body.code
        ).trim();
    }

    if (
      req.body.description != null
    ) {
      subject.description =
        String(
          req.body.description
        ).trim();
    }

    write(
      'subjects',
      subjects
    );

    res.json({
      ok: true,
      subject
    });
  }
);

app.delete(
  '/api/subjects/:id',
  auth,
  role(
    'school_admin',
    'superadmin'
  ),
  (req, res) => {
    let subjects =
      read('subjects');

    const subject =
      subjects.find(
        (item) =>
          item.id ===
          req.params.id
      );

    if (
      !subject ||
      !schoolScope(
        req,
        subject
      )
    ) {
      return res.status(404).json({
        error: 'Subject not found'
      });
    }

    subjects =
      subjects.filter(
        (item) =>
          item.id !==
          subject.id
      );

    write(
      'subjects',
      subjects
    );

    res.json({
      ok: true
    });
  }
);

/*
|--------------------------------------------------------------------------
| ANNOUNCEMENTS
|--------------------------------------------------------------------------
*/

app.get(
  '/api/announcements',
  auth,
  (req, res) => {
    const announcements =
      read('announcements')
        .filter(
          (item) =>
            schoolScope(
              req,
              item
            )
        )
        .sort(
          (a, b) =>
            String(
              b.createdAt
            ).localeCompare(
              String(
                a.createdAt
              )
            )
        );

    res.json(
      announcements
    );
  }
);

app.post(
  '/api/announcements',
  auth,
  role(
    'school_admin',
    'teacher',
    'superadmin'
  ),
  (req, res) => {
    const schoolId =
      req.user.role ===
      'superadmin'
        ? req.body.schoolId
        : req.user.schoolId;

    if (
      !schoolId ||
      !schoolOf(schoolId)
    ) {
      return res.status(400).json({
        error: 'Valid school required'
      });
    }

    if (
      !req.body.title ||
      !req.body.body
    ) {
      return res.status(400).json({
        error:
          'Title and body required'
      });
    }

    let announcements =
      read('announcements');

    const announcement = {
      id: uid(),
      schoolId,
      title:
        String(
          req.body.title
        ).trim(),

      body:
        String(
          req.body.body
        ).trim(),

      createdBy:
        req.user.id,

      createdAt: now()
    };

    announcements.push(
      announcement
    );

    write(
      'announcements',
      announcements
    );

    res.json({
      ok: true,
      announcement
    });
  }
);

app.delete(
  '/api/announcements/:id',
  auth,
  role(
    'school_admin',
    'superadmin'
  ),
  (req, res) => {
    let announcements =
      read('announcements');

    const announcement =
      announcements.find(
        (item) =>
          item.id ===
          req.params.id
      );

    if (
      !announcement ||
      !schoolScope(
        req,
        announcement
      )
    ) {
      return res.status(404).json({
        error: 'Announcement not found'
      });
    }

    announcements =
      announcements.filter(
        (item) =>
          item.id !==
          announcement.id
      );

    write(
      'announcements',
      announcements
    );

    res.json({
      ok: true
    });
  }
);

/*
|--------------------------------------------------------------------------
| CBT / EXAMS
|--------------------------------------------------------------------------
*/

app.get(
  '/api/exams',
  auth,
  (req, res) => {
    const exams =
      read('exams')
        .filter(
          (exam) =>
            schoolScope(
              req,
              exam
            )
        );

    const results =
      read('results');

    res.json(
      exams.map(
        (exam) => ({
          ...exam,

          subject:
            subjectOf(
              exam.subjectId
            )?.name ||
            'Unknown subject',

          questionCount:
            questionsOf(
              exam.id
            ).length,

          submissionCount:
            results.filter(
              (result) =>
                result.examId ===
                exam.id
            ).length
        })
      )
    );
  }
);

app.get(
  '/api/exams/:id',
  auth,
  (req, res) => {
    const exam =
      examOf(
        req.params.id
      );

    if (
      !exam ||
      !schoolScope(
        req,
        exam
      )
    ) {
      return res.status(404).json({
        error: 'Exam not found'
      });
    }

    res.json({
      ...exam,

      subject:
        subjectOf(
          exam.subjectId
        ),

      questions:
        questionsOf(
          exam.id
        ),

      questionCount:
        questionsOf(
          exam.id
        ).length,

      submissionCount:
        read('results').filter(
          (result) =>
            result.examId ===
            exam.id
        ).length
    });
  }
);

app.post(
  '/api/exams',
  auth,
  role(
    'school_admin',
    'teacher',
    'superadmin'
  ),
  (req, res) => {
    const schoolId =
      req.user.role ===
      'superadmin'
        ? req.body.schoolId
        : req.user.schoolId;

    const subject =
      read('subjects').find(
        (item) =>
          item.id ===
            req.body.subjectId &&
          item.schoolId ===
            schoolId
      );

    if (!subject) {
      return res.status(400).json({
        error: 'Invalid subject'
      });
    }

    const title =
      String(
        req.body.title ||
          'Untitled CBT'
      ).trim();

    if (!title) {
      return res.status(400).json({
        error: 'Exam title required'
      });
    }

    const exam = {
      id: uid(),
      schoolId,
      subjectId:
        subject.id,

      title,

      duration:
        Math.max(
          1,
          Number(
            req.body.duration
          ) || 30
        ),

      instructions:
        String(
          req.body.instructions ||
            ''
        ),

      status:
        req.body.status ===
        'published'
          ? 'published'
          : 'draft',

      createdBy:
        req.user.id,

      createdAt: now()
    };

    let exams =
      read('exams');

    exams.push(exam);

    write(
      'exams',
      exams
    );

    res.json({
      ok: true,
      exam
    });
  }
);

app.put(
  '/api/exams/:id',
  auth,
  role(
    'school_admin',
    'teacher',
    'superadmin'
  ),
  (req, res) => {
    let exams =
      read('exams');

    const exam =
      exams.find(
        (item) =>
          item.id ===
          req.params.id
      );

    if (
      !exam ||
      !schoolScope(
        req,
        exam
      )
    ) {
      return res.status(404).json({
        error: 'Exam not found'
      });
    }

    if (req.body.title != null) {
      exam.title =
        String(
          req.body.title
        ).trim();
    }

    if (
      req.body.instructions !=
      null
    ) {
      exam.instructions =
        String(
          req.body.instructions
        );
    }

    if (
      req.body.status ===
        'draft' ||
      req.body.status ===
        'published'
    ) {
      exam.status =
        req.body.status;
    }

    if (req.body.duration != null) {
      exam.duration =
        Math.max(
          1,
          Number(
            req.body.duration
          ) || 30
        );
    }

    if (req.body.subjectId) {
      const subject =
        read('subjects').find(
          (item) =>
            item.id ===
              req.body.subjectId &&
            item.schoolId ===
              exam.schoolId
        );

      if (!subject) {
        return res.status(400).json({
          error:
            'Invalid subject'
        });
      }

      exam.subjectId =
        subject.id;
    }

    write(
      'exams',
      exams
    );

    res.json({
      ok: true,
      exam
    });
  }
);

app.delete(
  '/api/exams/:id',
  auth,
  role(
    'school_admin',
    'teacher',
    'superadmin'
  ),
  (req, res) => {
    let exams =
      read('exams');

    const exam =
      exams.find(
        (item) =>
          item.id ===
          req.params.id
      );

    if (
      !exam ||
      !schoolScope(
        req,
        exam
      )
    ) {
      return res.status(404).json({
        error: 'Exam not found'
      });
    }

    exams =
      exams.filter(
        (item) =>
          item.id !==
          exam.id
      );

    write(
      'exams',
      exams
    );

    write(
      'questions',
      read('questions').filter(
        (question) =>
          question.examId !==
          exam.id
      )
    );

    write(
      'results',
      read('results').filter(
        (result) =>
          result.examId !==
          exam.id
      )
    );

    res.json({
      ok: true
    });
  }
);

/*
|--------------------------------------------------------------------------
| ADD QUESTION
|--------------------------------------------------------------------------
*/

app.post(
  '/api/exams/:id/questions',
  auth,
  role(
    'school_admin',
    'teacher',
    'superadmin'
  ),
  (req, res) => {
    const exam =
      examOf(
        req.params.id
      );

    if (
      !exam ||
      !schoolScope(
        req,
        exam
      )
    ) {
      return res.status(404).json({
        error: 'Exam not found'
      });
    }

    const {
      question,
      options,
      answer,
      points,
      difficulty,
      explanation,
      tags
    } = req.body;

    if (
      !question ||
      !Array.isArray(options) ||
      options.length < 2
    ) {
      return res.status(400).json({
        error:
          'Question and options are required'
      });
    }

    const correctAnswer =
      Number(answer);

    if (
      !Number.isInteger(
        correctAnswer
      ) ||
      correctAnswer < 0 ||
      correctAnswer >=
        options.length
    ) {
      return res.status(400).json({
        error:
          'Invalid correct answer'
      });
    }

    const item = {
      id: uid(),
      examId: exam.id,
      schoolId: exam.schoolId,
      question:
        String(question).trim(),
      options:
        options.map(
          (option) =>
            String(option)
        ),
      answer: correctAnswer,
      points:
        Math.max(
          1,
          Number(points) || 1
        ),
      difficulty:
        difficulty ||
        'medium',
      explanation:
        explanation || '',
      tags:
        tags || '',
      createdAt: now(),
      createdBy:
        req.user.id
    };

    let questions =
      read('questions');

    questions.push(item);

    write(
      'questions',
      questions
    );

    res.json({
      ok: true,
      question: item
    });
  }
);

/*
|--------------------------------------------------------------------------
| GET QUESTIONS FOR EXAM
|--------------------------------------------------------------------------
*/

app.get(
  '/api/exams/:id/questions',
  auth,
  role(
    'school_admin',
    'teacher',
    'superadmin'
  ),
  (req, res) => {
    const exam =
      examOf(
        req.params.id
      );

    if (
      !exam ||
      !schoolScope(
        req,
        exam
      )
    ) {
      return res.status(404).json({
        error: 'Exam not found'
      });
    }

    res.json(
      questionsOf(
        exam.id
      )
    );
  }
);

/*
|--------------------------------------------------------------------------
| UPDATE QUESTION
|--------------------------------------------------------------------------
*/

app.put(
  '/api/questions/:id',
  auth,
  role(
    'school_admin',
    'teacher',
    'superadmin'
  ),
  (req, res) => {
    let questions =
      read('questions');

    const question =
      questions.find(
        (item) =>
          item.id ===
          req.params.id
      );

    if (
      !question ||
      !schoolScope(
        req,
        question
      )
    ) {
      return res.status(404).json({
        error: 'Question not found'
      });
    }

    if (req.body.question != null) {
      question.question =
        String(
          req.body.question
        ).trim();
    }

    if (
      Array.isArray(
        req.body.options
      )
    ) {
      question.options =
        req.body.options.map(
          (option) =>
            String(option)
        );
    }

    if (req.body.answer != null) {
      const answer =
        Number(
          req.body.answer
        );

      if (
        !Number.isInteger(
          answer
        ) ||
        answer < 0 ||
        answer >=
          question.options.length
      ) {
        return res.status(400).json({
          error:
            'Invalid correct answer'
        });
      }

      question.answer =
        answer;
    }

    if (req.body.points != null) {
      question.points =
        Math.max(
          1,
          Number(
            req.body.points
          ) || 1
        );
    }

    if (
      req.body.difficulty !=
      null
    ) {
      question.difficulty =
        req.body.difficulty;
    }

    if (
      req.body.explanation !=
      null
    ) {
      question.explanation =
        req.body.explanation;
    }

    if (req.body.tags != null) {
      question.tags =
        req.body.tags;
    }

    write(
      'questions',
      questions
    );

    res.json({
      ok: true,
      question
    });
  }
);

/*
|--------------------------------------------------------------------------
| DELETE QUESTION
|--------------------------------------------------------------------------
*/

app.delete(
  '/api/questions/:id',
  auth,
  role(
    'school_admin',
    'teacher',
    'superadmin'
  ),
  (req, res) => {
    let questions =
      read('questions');

    const question =
      questions.find(
        (item) =>
          item.id ===
          req.params.id
      );

    if (
      !question ||
      !schoolScope(
        req,
        question
      )
    ) {
      return res.status(404).json({
        error: 'Question not found'
      });
    }

    questions =
      questions.filter(
        (item) =>
          item.id !==
          question.id
      );

    write(
      'questions',
      questions
    );

    res.json({
      ok: true
    });
  }
);

/*
|--------------------------------------------------------------------------
| QUESTION BANK
|--------------------------------------------------------------------------
*/

app.get(
  '/api/question-bank',
  auth,
  role(
    'school_admin',
    'teacher',
    'superadmin'
  ),
  (req, res) => {
    const {
      search,
      subjectId,
      difficulty,
      tags
    } = req.query;

    let questions =
      read('questions')
        .filter(
          (question) =>
            schoolScope(
              req,
              question
            )
        );

    if (subjectId) {
      const examIds =
        new Set(
          read('exams')
            .filter(
              (exam) =>
                exam.subjectId ===
                subjectId
            )
            .map(
              (exam) =>
                exam.id
            )
        );

      questions =
        questions.filter(
          (question) =>
            examIds.has(
              question.examId
            )
        );
    }

    if (difficulty) {
      questions =
        questions.filter(
          (question) =>
            String(
              question.difficulty ||
                ''
            ).toLowerCase() ===
            String(
              difficulty
            ).toLowerCase()
        );
    }

    if (tags) {
      const searchTags =
        String(tags)
          .toLowerCase();

      questions =
        questions.filter(
          (question) =>
            String(
              question.tags ||
                ''
            )
              .toLowerCase()
              .includes(
                searchTags
              )
        );
    }

    if (search) {
      const term =
        String(search)
          .toLowerCase();

      questions =
        questions.filter(
          (question) =>
            String(
              question.question ||
                ''
            )
              .toLowerCase()
              .includes(term)
        );
    }

    res.json(
      questions.map(
        (question) => ({
          ...question,

          exam:
            examOf(
              question.examId
            ),

          subject:
            subjectOf(
              examOf(
                question.examId
              )?.subjectId
            )
        })
      )
    );
  }
);

/*
|--------------------------------------------------------------------------
| BULK QUESTION UPLOAD
|--------------------------------------------------------------------------
*/

app.post(
  '/api/question-bank/bulk',
  auth,
  role(
    'school_admin',
    'teacher',
    'superadmin'
  ),
  (req, res) => {
    const {
      examId,
      questions
    } = req.body;

    if (
      !examId ||
      !Array.isArray(questions)
    ) {
      return res.status(400).json({
        error:
          'examId and questions array are required'
      });
    }

    const exam =
      examOf(examId);

    if (
      !exam ||
      !schoolScope(
        req,
        exam
      )
    ) {
      return res.status(404).json({
        error: 'Exam not found'
      });
    }

    let existing =
      read('questions');

    const created = [];

    for (const item of questions) {
      if (
        !item.question ||
        !Array.isArray(
          item.options
        )
      ) {
        continue;
      }

      const answer =
        Number(
          item.answer
        );

      if (
        !Number.isInteger(
          answer
        ) ||
        answer < 0 ||
        answer >=
          item.options.length
      ) {
        continue;
      }

      const question = {
        id: uid(),
        examId: exam.id,
        schoolId:
          exam.schoolId,
        question:
          String(
            item.question
          ).trim(),
        options:
          item.options.map(
            (option) =>
              String(option)
          ),
        answer,
        points:
          Math.max(
            1,
            Number(
              item.points
            ) || 1
          ),
        difficulty:
          item.difficulty ||
          'medium',
        explanation:
          item.explanation ||
          '',
        tags:
          item.tags ||
          '',
        createdAt: now(),
        createdBy:
          req.user.id
      };

      existing.push(question);
      created.push(question);
    }

    write(
      'questions',
      existing
    );

    res.json({
      ok: true,
      created: created.length,
      questions: created
    });
  }
);

/*
|--------------------------------------------------------------------------
| STUDENT: TAKE EXAM
|--------------------------------------------------------------------------
*/

app.get(
  '/api/exams/:id/take',
  auth,
  role('student'),
  (req, res) => {
    const exam =
      examOf(
        req.params.id
      );

    if (
      !exam ||
      exam.schoolId !==
        req.user.schoolId
    ) {
      return res.status(404).json({
        error: 'Exam not found'
      });
    }

    if (
      exam.status !==
      'published'
    ) {
      return res.status(400).json({
        error:
          'This CBT is not published'
      });
    }

    const previous =
      read('results').find(
        (result) =>
          result.examId ===
            exam.id &&
          result.studentId ===
            req.user.id
      );

    if (previous) {
      return res.status(409).json({
        error:
          'You have already submitted this CBT',
        result: previous
      });
    }

    const questions =
      questionsOf(
        exam.id
      ).map(
        (question) => ({
          id: question.id,
          question:
            question.question,
          options:
            question.options,
          points:
            question.points,
          difficulty:
            question.difficulty,
          tags:
            question.tags
        })
      );

    res.json({
      exam: {
        id: exam.id,
        title: exam.title,
        duration:
          exam.duration,
        instructions:
          exam.instructions,
        subject:
          subjectOf(
            exam.subjectId
          )
      },

      questions
    });
  }
);

/*
|--------------------------------------------------------------------------
| STUDENT: SUBMIT EXAM
|--------------------------------------------------------------------------
*/

app.post(
  '/api/exams/:id/submit',
  auth,
  role('student'),
  (req, res) => {
    const exam =
      examOf(
        req.params.id
      );

    if (
      !exam ||
      exam.schoolId !==
        req.user.schoolId
    ) {
      return res.status(404).json({
        error: 'Exam not found'
      });
    }

    if (
      exam.status !==
      'published'
    ) {
      return res.status(400).json({
        error:
          'This CBT is not published'
      });
    }

    let results =
      read('results');

    const existing =
      results.find(
        (result) =>
          result.examId ===
            exam.id &&
          result.studentId ===
            req.user.id
      );

    if (existing) {
      return res.status(409).json({
        error:
          'You have already submitted this CBT',
        result: existing
      });
    }

    const submittedAnswers =
      req.body.answers || {};

    const questions =
      questionsOf(
        exam.id
      );

    let score = 0;
    let total = 0;
    let correct = 0;

    for (const question of questions) {
      const points =
        Math.max(
          1,
          Number(
            question.points
          ) || 1
        );

      total += points;

      const selected =
        submittedAnswers[
          question.id
        ];

      if (
        Number(selected) ===
        Number(question.answer)
      ) {
        score += points;
        correct++;
      }
    }

    const percentage =
      total > 0
        ? Math.round(
            (score / total) *
              10000
          ) / 100
        : 0;

    const result = {
      id: uid(),
      examId: exam.id,
      schoolId:
        exam.schoolId,
      studentId:
        req.user.id,
      studentName:
        req.user.fullName,
      examTitle:
        exam.title,
      score,
      total,
      correct,
      wrong:
        Math.max(
          0,
          questions.length -
            correct
        ),
      percentage,
      answers:
        submittedAnswers,
      submittedAt: now()
    };

    results.push(result);

    write(
      'results',
      results
    );

    res.json({
      ok: true,
      result
    });
  }
);

/*
|--------------------------------------------------------------------------
| RESULTS
|--------------------------------------------------------------------------
*/

app.get(
  '/api/results',
  auth,
  (req, res) => {
    let results =
      read('results');

    if (req.user.role === 'student') {
      results =
        results.filter(
          (result) =>
            result.schoolId ===
              req.user.schoolId &&
            result.studentId ===
              req.user.id
        );
    } else if (
      req.user.role !==
      'superadmin'
    ) {
      results =
        results.filter(
          (result) =>
            result.schoolId ===
            req.user.schoolId
        );
    }

    res.json(
      results.sort(
        (a, b) =>
          String(
            b.submittedAt
          ).localeCompare(
            String(
              a.submittedAt
            )
          )
      )
    );
  }
);

app.get(
  '/api/results/:id',
  auth,
  (req, res) => {
    const result =
      read('results').find(
        (item) =>
          item.id ===
          req.params.id
      );

    if (!result) {
      return res.status(404).json({
        error: 'Result not found'
      });
    }

    if (
      req.user.role ===
      'student'
    ) {
      if (
        result.studentId !==
        req.user.id
      ) {
        return res.status(403).json({
          error:
            'Permission denied'
        });
      }
    } else if (
      req.user.role !==
      'superadmin' &&
      result.schoolId !==
        req.user.schoolId
    ) {
      return res.status(403).json({
        error:
          'Permission denied'
      });
    }

    res.json({
      result
    });
  }
);

/*
|--------------------------------------------------------------------------
| SUPERADMIN - SCHOOLS
|--------------------------------------------------------------------------
*/

app.get(
  '/api/superadmin/schools',
  auth,
  role('superadmin'),
  (req, res) => {
    const schools =
      read('schools');

    res.json(
      schools
    );
  }
);

app.post(
  '/api/superadmin/schools',
  auth,
  role('superadmin'),
  (req, res) => {
    const name =
      String(
        req.body.name ||
          ''
      ).trim();

    if (!name) {
      return res.status(400).json({
        error:
          'School name required'
      });
    }

    let schools =
      read('schools');

    const school = {
      id: uid(),
      name,
      motto:
        String(
          req.body.motto ||
            ''
        ).trim(),
      logo: '',
      primaryColor:
        req.body.primaryColor ||
        '#2563eb',
      secondaryColor:
        req.body.secondaryColor ||
        '#16a34a',
      theme:
        req.body.theme ||
        'light',
      active: true,
      createdAt: now()
    };

    schools.push(school);

    write(
      'schools',
      schools
    );

    res.json({
      ok: true,
      school
    });
  }
);

app.put(
  '/api/superadmin/schools/:id',
  auth,
  role('superadmin'),
  (req, res) => {
    let schools =
      read('schools');

    const school =
      schools.find(
        (item) =>
          item.id ===
          req.params.id
      );

    if (!school) {
      return res.status(404).json({
        error: 'School not found'
      });
    }

    for (const key of [
      'name',
      'motto',
      'primaryColor',
      'secondaryColor',
      'theme',
      'active'
    ]) {
      if (req.body[key] != null) {
        school[key] =
          req.body[key];
      }
    }

    write(
      'schools',
      schools
    );

    res.json({
      ok: true,
      school
    });
  }
);

/*
|--------------------------------------------------------------------------
| SUPERADMIN - ALL USERS
|--------------------------------------------------------------------------
*/

app.get(
  '/api/superadmin/all-users',
  auth,
  role('superadmin'),
  (req, res) => {
    res.json(
      read('users').map(safe)
    );
  }
);

/*
|--------------------------------------------------------------------------
| GOOGLE AUTH
|--------------------------------------------------------------------------
*/

const googleConfigured =
  Boolean(
    process.env.GOOGLE_CLIENT_ID &&
      process.env.GOOGLE_CLIENT_SECRET &&
      process.env.GOOGLE_CALLBACK_URL
  );

if (googleConfigured) {
  passport.use(
    new GoogleStrategy(
      {
        clientID:
          process.env.GOOGLE_CLIENT_ID,

        clientSecret:
          process.env.GOOGLE_CLIENT_SECRET,

        callbackURL:
          process.env.GOOGLE_CALLBACK_URL
      },

      async (
        accessToken,
        refreshToken,
        profile,
        done
      ) => {
        try {
          let users =
            read('users');

          const email =
            profile.emails?.[0]?.value
              ?.toLowerCase();

          let user =
            users.find(
              (item) =>
                item.providerId ===
                  profile.id ||
                (
                  email &&
                  item.email?.toLowerCase() ===
                    email
                )
            );

          if (!user) {
            return done(
              null,
              false,
              {
                message:
                  'No SchoolHub account is linked to this Google account. Ask your school administrator to create your account first.'
              }
            );
          }

          if (
            user.active === false
          ) {
            return done(
              null,
              false,
              {
                message:
                  'This account is inactive.'
              }
            );
          }

          user.provider =
            'google';

          user.providerId =
            profile.id;

          if (
            !user.profilePicture &&
            profile.photos?.[0]?.value
          ) {
            user.profilePicture =
              profile.photos[0].value;
          }

          write(
            'users',
            users
          );

          done(null, user);
        } catch (error) {
          done(
            error,
            null
          );
        }
      }
    )
  );
}

passport.serializeUser(
  (user, done) => {
    done(null, user.id);
  }
);

passport.deserializeUser(
  (id, done) => {
    const user =
      userOf(id);

    done(
      null,
      user || false
    );
  }
);

app.get(
  '/auth/google',
  (req, res, next) => {
    if (!googleConfigured) {
      return res.status(503).send(
        'Google authentication is not configured.'
      );
    }

    passport.authenticate(
      'google',
      {
        scope: [
          'profile',
          'email'
        ],
        prompt: 'select_account'
      }
    )(req, res, next);
  }
);

app.get(
  '/auth/google/callback',
  (req, res, next) => {
    if (!googleConfigured) {
      return res.status(503).send(
        'Google authentication is not configured.'
      );
    }

    passport.authenticate(
      'google',
      (error, user, info) => {
        if (error) {
          console.error(
            'GOOGLE CALLBACK ERROR:',
            error
          );

          return res.redirect(
            '/login.html?error=google'
          );
        }

        if (!user) {
          console.error(
            'GOOGLE LOGIN FAILED:',
            info
          );

          return res.redirect(
            '/login.html?error=google'
          );
        }

        req.logIn(
          user,
          (loginError) => {
            if (loginError) {
              console.error(
                'GOOGLE SESSION ERROR:',
                loginError
              );

              return res.redirect(
                '/login.html?error=session'
              );
            }

            req.session.userId =
              user.id;

            req.session.save(
              (sessionError) => {
                if (sessionError) {
                  console.error(
                    'GOOGLE SESSION SAVE ERROR:',
                    sessionError
                  );

                  return res.redirect(
                    '/login.html?error=session'
                  );
                }

                let redirect =
                  '/admin.html';

                if (
                  user.role ===
                  'student'
                ) {
                  redirect =
                    '/student.html';
                } else if (
                  user.role ===
                  'teacher'
                ) {
                  redirect =
                    '/teacher.html';
                }

                res.redirect(
                  redirect
                );
              }
            );
          }
        );
      }
    )(req, res, next);
  }
);

/*
|--------------------------------------------------------------------------
| 404 API HANDLER
|--------------------------------------------------------------------------
*/

app.use(
  '/api',
  (req, res) => {
    res.status(404).json({
      error:
        'API route not found'
    });
  }
);

/*
|--------------------------------------------------------------------------
| FRONTEND FALLBACK
|--------------------------------------------------------------------------
*/

app.get(
  '*',
  (req, res) => {
    const indexPath =
      path.join(
        ROOT,
        'public',
        'index.html'
      );

    if (
      fs.existsSync(indexPath)
    ) {
      return res.sendFile(
        indexPath
      );
    }

    res.status(404).send(
      'SchoolHub Pro frontend not found.'
    );
  }
);

/*
|--------------------------------------------------------------------------
| SERVER START
|--------------------------------------------------------------------------
|
| IMPORTANT FOR RAILWAY:
| Railway provides process.env.PORT.
|
*/

app.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.log(
      '=================================================='
    );

    console.log(
      'SchoolHub Pro server started'
    );

    console.log(
      `Port: ${PORT}`
    );

    console.log(
      `Storage: ${STORAGE_ROOT}`
    );

    console.log(
      `Environment: ${
        process.env.NODE_ENV ||
        'development'
      }`
    );

    console.log(
      `Google Auth: ${
        googleConfigured
          ? 'CONFIGURED'
          : 'NOT CONFIGURED'
      }`
    );

    console.log(
      '=================================================='
    );
  }
);

/*
|--------------------------------------------------------------------------
| SERVER ERROR HANDLING
|--------------------------------------------------------------------------
*/

process.on(
  'uncaughtException',
  (error) => {
    console.error(
      'UNCAUGHT EXCEPTION:',
      error
    );
  }
);

process.on(
  'unhandledRejection',
  (error) => {
    console.error(
      'UNHANDLED REJECTION:',
      error
    );
  }
);
