/*
=========================================================
 SCHOOLHUB PRO - MAIN SERVER
 Multi-School School Management + CBT Platform
 Version: 6.0.0

 ROLES
 - superadmin
 - school_admin
 - teacher
 - student

 STORAGE
 - Local: ./data
 - Railway: /app/storage

 GOOGLE OAUTH
 - Passport Google OAuth 2.0

 NO PARENT DASHBOARD
=========================================================
*/

require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

/* =====================================================
   APP
===================================================== */

const app = express();

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";

const IS_PRODUCTION = process.env.NODE_ENV === "production";

const STORAGE_ROOT =
  process.env.STORAGE_ROOT ||
  path.join(__dirname, "data");

const PUBLIC_DIR = path.join(__dirname, "public");
const DATA_DIR = STORAGE_ROOT;

/* =====================================================
   CREATE DIRECTORIES
===================================================== */

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

ensureDir(STORAGE_ROOT);
ensureDir(PUBLIC_DIR);

/* =====================================================
   DATABASE FILES
===================================================== */

const FILES = {
  users: path.join(DATA_DIR, "users.json"),
  schools: path.join(DATA_DIR, "schools.json"),
  settings: path.join(DATA_DIR, "settings.json"),
  subjects: path.join(DATA_DIR, "subjects.json"),
  exams: path.join(DATA_DIR, "exams.json"),
  questions: path.join(DATA_DIR, "questions.json"),
  results: path.join(DATA_DIR, "results.json"),
  announcements: path.join(DATA_DIR, "announcements.json")
};

/* =====================================================
   DEFAULT DATABASE
===================================================== */

const DEFAULTS = {
  users: [],
  schools: [],
  settings: {
    platformName: "SchoolHub Pro",
    platformDescription:
      "Smart school management for modern schools.",
    defaultTheme: "light",
    maintenanceMode: false
  },
  subjects: [],
  exams: [],
  questions: [],
  results: [],
  announcements: []
};

/* =====================================================
   JSON DATABASE HELPERS
===================================================== */

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function ensureJsonFile(file, fallback) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(
      file,
      JSON.stringify(fallback, null, 2),
      "utf8"
    );
  }
}

Object.keys(FILES).forEach((key) => {
  ensureJsonFile(FILES[key], DEFAULTS[key]);
});

function readJson(file, fallback = []) {
  try {
    if (!fs.existsSync(file)) {
      writeJson(file, fallback);
      return clone(fallback);
    }

    const raw = fs.readFileSync(file, "utf8").trim();

    if (!raw) {
      writeJson(file, fallback);
      return clone(fallback);
    }

    return JSON.parse(raw);
  } catch (error) {
    console.error("JSON READ ERROR:", file, error.message);
    return clone(fallback);
  }
}

function writeJson(file, data) {
  const tempFile = `${file}.tmp`;

  fs.writeFileSync(
    tempFile,
    JSON.stringify(data, null, 2),
    "utf8"
  );

  fs.renameSync(tempFile, file);
}

function getUsers() {
  return readJson(FILES.users, []);
}

function saveUsers(data) {
  writeJson(FILES.users, data);
}

function getSchools() {
  return readJson(FILES.schools, []);
}

function saveSchools(data) {
  writeJson(FILES.schools, data);
}

function getSettings() {
  return readJson(FILES.settings, DEFAULTS.settings);
}

function saveSettings(data) {
  writeJson(FILES.settings, data);
}

function getSubjects() {
  return readJson(FILES.subjects, []);
}

function saveSubjects(data) {
  writeJson(FILES.subjects, data);
}

function getExams() {
  return readJson(FILES.exams, []);
}

function saveExams(data) {
  writeJson(FILES.exams, data);
}

function getQuestions() {
  return readJson(FILES.questions, []);
}

function saveQuestions(data) {
  writeJson(FILES.questions, data);
}

function getResults() {
  return readJson(FILES.results, []);
}

function saveResults(data) {
  writeJson(FILES.results, data);
}

function getAnnouncements() {
  return readJson(FILES.announcements, []);
}

function saveAnnouncements(data) {
  writeJson(FILES.announcements, data);
}

/* =====================================================
   HELPERS
===================================================== */

function id(prefix = "id") {
  return `${prefix}_${crypto.randomUUID()}`;
}

function now() {
  return new Date().toISOString();
}

function clean(value) {
  return String(value ?? "").trim();
}

function normalizeEmail(value) {
  return clean(value).toLowerCase();
}

function normalizeUsername(value) {
  return clean(value).toLowerCase();
}

function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function publicUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    fullName: user.fullName || "",
    username: user.username || "",
    email: user.email || "",
    role: user.role || "",
    schoolId: user.schoolId || null,
    profilePicture: user.profilePicture || "",
    active: user.active !== false,
    provider: user.provider || "local",
    createdAt: user.createdAt || null
  };
}

function getSchoolById(schoolId) {
  if (!schoolId) return null;

  return getSchools().find(
    (school) => school.id === schoolId
  ) || null;
}

function getUserById(userId) {
  return getUsers().find(
    (user) => user.id === userId
  ) || null;
}

function getUserByEmail(email) {
  const normalized = normalizeEmail(email);

  return getUsers().find(
    (user) =>
      normalizeEmail(user.email) === normalized
  ) || null;
}

function getUserByUsername(username) {
  const normalized = normalizeUsername(username);

  return getUsers().find(
    (user) =>
      normalizeUsername(user.username) === normalized
  ) || null;
}

function roleRedirect(role) {
  if (
    role === "superadmin" ||
    role === "school_admin"
  ) {
    return "/admin.html";
  }

  if (role === "teacher") {
    return "/teacher.html";
  }

  if (role === "student") {
    return "/student.html";
  }

  return "/login.html";
}

function sameSchool(user, schoolId) {
  if (!user) return false;

  if (user.role === "superadmin") {
    return true;
  }

  return Boolean(
    user.schoolId &&
    schoolId &&
    user.schoolId === schoolId
  );
}

/* =====================================================
   EXPRESS CONFIG
===================================================== */

app.disable("x-powered-by");

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

/* =====================================================
   SESSION
===================================================== */

const sessionSecret =
  process.env.SESSION_SECRET ||
  "CHANGE_THIS_SESSION_SECRET_IN_PRODUCTION";

app.use(
  session({
    secret: sessionSecret,

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,

      secure: IS_PRODUCTION,

      sameSite: "lax",

      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

/* =====================================================
   PASSPORT
===================================================== */

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((userId, done) => {
  const user = getUserById(userId);

  if (!user) {
    return done(null, false);
  }

  done(null, user);
});

/* =====================================================
   GOOGLE AUTH CONFIG
===================================================== */

const GOOGLE_CLIENT_ID =
  process.env.GOOGLE_CLIENT_ID || "";

const GOOGLE_CLIENT_SECRET =
  process.env.GOOGLE_CLIENT_SECRET || "";

const GOOGLE_CALLBACK_URL =
  process.env.GOOGLE_CALLBACK_URL ||
  "http://localhost:3000/auth/google/callback";

const googleConfigured =
  Boolean(
    GOOGLE_CLIENT_ID &&
    GOOGLE_CLIENT_SECRET &&
    GOOGLE_CALLBACK_URL
  );

/* =====================================================
   GOOGLE STRATEGY
===================================================== */

if (googleConfigured) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: GOOGLE_CALLBACK_URL
      },

      async (accessToken, refreshToken, profile, done) => {
        try {
          const users = getUsers();

          const googleId = profile.id;

          const email =
            normalizeEmail(
              profile.emails?.[0]?.value || ""
            );

          const displayName =
            profile.displayName ||
            profile.name?.givenName ||
            "Google User";

          if (!email) {
            return done(
              new Error(
                "Google did not provide an email address."
              )
            );
          }

          let user =
            users.find(
              (item) =>
                item.googleId === googleId
            ) ||
            users.find(
              (item) =>
                normalizeEmail(item.email) === email
            );

          if (!user) {
            return done(
              new Error(
                "No SchoolHub account exists for this Google email. Please register first."
              )
            );
          }

          if (user.active === false) {
            return done(
              new Error(
                "This SchoolHub account has been disabled."
              )
            );
          }

          user.googleId = googleId;
          user.provider = "google";
          user.updatedAt = now();

          if (
            !user.profilePicture &&
            profile.photos?.[0]?.value
          ) {
            user.profilePicture =
              profile.photos[0].value;
          }

          saveUsers(users);

          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );
}

/* =====================================================
   AUTH MIDDLEWARE
===================================================== */

function requireAuth(req, res, next) {
  const user = getUserById(req.session.userId);

  if (!user) {
    return res.status(401).json({
      ok: false,
      error: "Authentication required."
    });
  }

  if (user.active === false) {
    req.session.destroy(() => {});

    return res.status(403).json({
      ok: false,
      error: "Your account has been disabled."
    });
  }

  req.currentUser = user;

  next();
}

function requireSuperadmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.currentUser.role !== "superadmin") {
      return res.status(403).json({
        ok: false,
        error: "Superadmin access required."
      });
    }

    next();
  });
}

function requireSchoolAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (
      req.currentUser.role !== "school_admin" &&
      req.currentUser.role !== "superadmin"
    ) {
      return res.status(403).json({
        ok: false,
        error: "School administrator access required."
      });
    }

    next();
  });
}

function requireTeacher(req, res, next) {
  requireAuth(req, res, () => {
    if (
      req.currentUser.role !== "teacher" &&
      req.currentUser.role !== "school_admin" &&
      req.currentUser.role !== "superadmin"
    ) {
      return res.status(403).json({
        ok: false,
        error: "Teacher access required."
      });
    }

    next();
  });
}

/* =====================================================
   HEALTH
===================================================== */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    status: "online",
    service: "SchoolHub Pro",
    version: "6.0.0",
    environment:
      process.env.NODE_ENV || "development",
    port: PORT,
    storage: STORAGE_ROOT,
    googleAuth:
      googleConfigured
        ? "CONFIGURED"
        : "NOT_CONFIGURED",
    time: now()
  });
});

/* =====================================================
   PLATFORM
===================================================== */

app.get("/api/platform", (req, res) => {
  const settings = getSettings();

  res.json({
    ok: true,

    platform: {
      name:
        settings.platformName ||
        "SchoolHub Pro",

      description:
        settings.platformDescription ||
        "",

      defaultTheme:
        settings.defaultTheme ||
        "light",

      maintenanceMode:
        Boolean(settings.maintenanceMode)
    }
  });
});

app.get(
  "/api/platform-config",
  (req, res) => {
    const settings = getSettings();

    res.json({
      ok: true,
      settings
    });
  }
);

/* =====================================================
   CURRENT USER
===================================================== */

app.get("/api/me", requireAuth, (req, res) => {
  const school =
    req.currentUser.schoolId
      ? getSchoolById(
          req.currentUser.schoolId
        )
      : null;

  res.json({
    ok: true,

    user: publicUser(req.currentUser),

    school,

    redirect:
      roleRedirect(
        req.currentUser.role
      )
  });
});

/* =====================================================
   REGISTER SCHOOL
===================================================== */

app.post("/api/register", async (req, res) => {
  try {
    const {
      schoolName,
      schoolMotto,
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
        ok: false,
        error:
          "School name, full name, username, email and password are required."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        ok: false,
        error:
          "Password must contain at least 6 characters."
      });
    }

    const normalizedEmail =
      normalizeEmail(email);

    const normalizedUsername =
      normalizeUsername(username);

    const users = getUsers();

    if (
      users.some(
        (user) =>
          normalizeEmail(user.email) ===
          normalizedEmail
      )
    ) {
      return res.status(409).json({
        ok: false,
        error:
          "An account with this email already exists."
      });
    }

    if (
      users.some(
        (user) =>
          normalizeUsername(user.username) ===
          normalizedUsername
      )
    ) {
      return res.status(409).json({
        ok: false,
        error:
          "This username is already in use."
      });
    }

    const schools = getSchools();

    const school = {
      id: id("school"),

      name: clean(schoolName),

      motto: clean(schoolMotto),

      logo: "",

      primaryColor: "#2563eb",

      secondaryColor: "#16a34a",

      theme: "light",

      active: true,

      createdAt: now(),

      updatedAt: now()
    };

    schools.push(school);

    saveSchools(schools);

    const passwordHash =
      await bcrypt.hash(password, 12);

    const user = {
      id: id("user"),

      fullName: clean(fullName),

      username: normalizedUsername,

      email: normalizedEmail,

      passwordHash,

      role: "school_admin",

      schoolId: school.id,

      profilePicture: "",

      provider: "local",

      active: true,

      createdAt: now(),

      updatedAt: now()
    };

    users.push(user);

    saveUsers(users);

    req.session.userId = user.id;

    req.login(user, (loginError) => {
      if (loginError) {
        console.error(
          "Register session error:",
          loginError
        );
      }

      return res.status(201).json({
        ok: true,

        message:
          "School account created successfully.",

        user: publicUser(user),

        school,

        redirect: "/admin.html"
      });
    });
  } catch (error) {
    console.error(
      "REGISTER ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      error: "Registration failed."
    });
  }
});

/* =====================================================
   NORMAL LOGIN
===================================================== */

app.post("/api/login", async (req, res) => {
  try {
    const identifier =
      clean(
        req.body.identifier ||
        req.body.email ||
        req.body.username
      );

    const password =
      String(req.body.password || "");

    if (!identifier || !password) {
      return res.status(400).json({
        ok: false,
        error:
          "Username/email and password are required."
      });
    }

    const users = getUsers();

    const normalized =
      identifier.toLowerCase();

    const user =
      users.find(
        (item) =>
          normalizeEmail(item.email) ===
            normalized ||
          normalizeUsername(item.username) ===
            normalized
      );

    if (!user) {
      return res.status(401).json({
        ok: false,
        error:
          "Invalid username/email or password."
      });
    }

    if (user.active === false) {
      return res.status(403).json({
        ok: false,
        error:
          "Your account has been disabled."
      });
    }

    if (!user.passwordHash) {
      return res.status(401).json({
        ok: false,
        error:
          "This account does not have a local password. Use Google Sign-In."
      });
    }

    const passwordMatches =
      await bcrypt.compare(
        password,
        user.passwordHash
      );

    if (!passwordMatches) {
      return res.status(401).json({
        ok: false,
        error:
          "Invalid username/email or password."
      });
    }

    req.session.userId = user.id;

    req.login(user, (loginError) => {
      if (loginError) {
        console.error(
          "LOGIN SESSION ERROR:",
          loginError
        );

        return res.status(500).json({
          ok: false,
          error:
            "Login session could not be created."
        });
      }

      return res.json({
        ok: true,

        message: "Login successful.",

        user: publicUser(user),

        redirect:
          roleRedirect(user.role)
      });
    });
  } catch (error) {
    console.error(
      "LOGIN ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      error:
        "An internal error occurred during login."
    });
  }
});

/* =====================================================
   LOGOUT
===================================================== */

app.post("/api/logout", (req, res) => {
  req.logout(() => {
    req.session.destroy(() => {
      res.json({
        ok: true,
        message: "Logged out successfully."
      });
    });
  });
});

/* =====================================================
   GOOGLE AUTH START
===================================================== */

app.get("/auth/google", (req, res, next) => {
  if (!googleConfigured) {
    return res.status(503).send(`
      <html>
        <head>
          <title>Google Sign-In</title>
          <meta name="viewport" content="width=device-width,initial-scale=1">
        </head>
        <body style="font-family:Arial;padding:40px">
          <h2>Google Sign-In is not configured.</h2>
          <p>Please configure GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_CALLBACK_URL.</p>
        </body>
      </html>
    `);
  }

  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account"
  })(req, res, next);
});

/* =====================================================
   GOOGLE CALLBACK
===================================================== */

app.get(
  "/auth/google/callback",
  (req, res, next) => {
    if (!googleConfigured) {
      return res.redirect(
        "/login.html?error=google_not_configured"
      );
    }

    passport.authenticate(
      "google",
      (error, user) => {
        if (error) {
          console.error(
            "GOOGLE CALLBACK ERROR:",
            error.message
          );

          return res.redirect(
            `/login.html?error=${encodeURIComponent(
              error.message ||
              "Google authentication failed."
            )}`
          );
        }

        if (!user) {
          return res.redirect(
            "/login.html?error=google_login_failed"
          );
        }

        req.logIn(
          user,
          (loginError) => {
            if (loginError) {
              console.error(
                "GOOGLE SESSION ERROR:",
                loginError
              );

              return res.redirect(
                "/login.html?error=session_error"
              );
            }

            req.session.userId = user.id;

            return res.redirect(
              roleRedirect(user.role)
            );
          }
        );
      }
    )(req, res, next);
  }
);

/* =====================================================
   SCHOOL
===================================================== */

app.get(
  "/api/school",
  requireAuth,
  (req, res) => {
    if (req.currentUser.role === "superadmin") {
      return res.json({
        ok: true,
        school: null
      });
    }

    const school =
      getSchoolById(
        req.currentUser.schoolId
      );

    if (!school) {
      return res.status(404).json({
        ok: false,
        error: "School not found."
      });
    }

    res.json({
      ok: true,
      school
    });
  }
);

/* =====================================================
   SCHOOL BRANDING
===================================================== */

app.put(
  "/api/school/branding",
  requireSchoolAdmin,
  (req, res) => {
    const {
      name,
      motto,
      logo,
      primaryColor,
      secondaryColor,
      theme
    } = req.body;

    if (req.currentUser.role === "superadmin") {
      return res.status(400).json({
        ok: false,
        error:
          "Superadmin should manage platform settings or a specific school."
      });
    }

    const schools = getSchools();

    const index =
      schools.findIndex(
        (school) =>
          school.id ===
          req.currentUser.schoolId
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error: "School not found."
      });
    }

    const school = schools[index];

    if (name !== undefined) {
      school.name = clean(name);
    }

    if (motto !== undefined) {
      school.motto = clean(motto);
    }

    if (logo !== undefined) {
      school.logo = clean(logo);
    }

    if (primaryColor !== undefined) {
      school.primaryColor =
        clean(primaryColor);
    }

    if (secondaryColor !== undefined) {
      school.secondaryColor =
        clean(secondaryColor);
    }

    if (theme !== undefined) {
      school.theme = clean(theme);
    }

    school.updatedAt = now();

    schools[index] = school;

    saveSchools(schools);

    res.json({
      ok: true,
      message:
        "School branding updated.",
      school
    });
  }
);

/* =====================================================
   USERS
===================================================== */

app.get(
  "/api/users",
  requireSchoolAdmin,
  (req, res) => {
    let users = getUsers();

    if (req.currentUser.role !== "superadmin") {
      users = users.filter(
        (user) =>
          user.schoolId ===
          req.currentUser.schoolId
      );
    }

    res.json({
      ok: true,
      users: users.map(publicUser)
    });
  }
);

/* =====================================================
   CREATE SCHOOL USER
===================================================== */

app.post(
  "/api/users",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const {
        fullName,
        username,
        email,
        password,
        role,
        schoolId
      } = req.body;

      if (
        !fullName ||
        !username ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Full name, username, email and password are required."
        });
      }

      const allowedRoles = [
        "teacher",
        "student"
      ];

      if (
        !allowedRoles.includes(role)
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "School admins can create teachers and students."
        });
      }

      const targetSchoolId =
        req.currentUser.role ===
        "superadmin"
          ? clean(schoolId)
          : req.currentUser.schoolId;

      if (!targetSchoolId) {
        return res.status(400).json({
          ok: false,
          error:
            "A school is required."
        });
      }

      const school =
        getSchoolById(targetSchoolId);

      if (!school) {
        return res.status(404).json({
          ok: false,
          error: "School not found."
        });
      }

      const users = getUsers();

      const normalizedEmail =
        normalizeEmail(email);

      const normalizedUsername =
        normalizeUsername(username);

      if (
        users.some(
          (user) =>
            normalizeEmail(user.email) ===
            normalizedEmail
        )
      ) {
        return res.status(409).json({
          ok: false,
          error:
            "Email is already registered."
        });
      }

      if (
        users.some(
          (user) =>
            normalizeUsername(
              user.username
            ) === normalizedUsername
        )
      ) {
        return res.status(409).json({
          ok: false,
          error:
            "Username is already registered."
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const user = {
        id: id("user"),

        fullName: clean(fullName),

        username: normalizedUsername,

        email: normalizedEmail,

        passwordHash,

        role,

        schoolId: targetSchoolId,

        profilePicture: "",

        provider: "local",

        active: true,

        createdAt: now(),

        updatedAt: now()
      };

      users.push(user);

      saveUsers(users);

      res.status(201).json({
        ok: true,
        message:
          "User created successfully.",
        user: publicUser(user)
      });
    } catch (error) {
      console.error(
        "CREATE USER ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Could not create user."
      });
    }
  }
);

/* =====================================================
   UPDATE USER
===================================================== */

app.put(
  "/api/users/:id",
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const users = getUsers();

      const index =
        users.findIndex(
          (user) =>
            user.id === req.params.id
        );

      if (index === -1) {
        return res.status(404).json({
          ok: false,
          error: "User not found."
        });
      }

      const user = users[index];

      if (
        req.currentUser.role !==
          "superadmin" &&
        user.schoolId !==
          req.currentUser.schoolId
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "You cannot manage users from another school."
        });
      }

      if (
        user.role === "superadmin" &&
        req.currentUser.role !==
          "superadmin"
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "You cannot manage a superadmin."
        });
      }

      if (req.body.fullName !== undefined) {
        user.fullName =
          clean(req.body.fullName);
      }

      if (req.body.username !== undefined) {
        user.username =
          normalizeUsername(
            req.body.username
          );
      }

      if (req.body.email !== undefined) {
        user.email =
          normalizeEmail(
            req.body.email
          );
      }

      if (req.body.role !== undefined) {
        if (
          req.currentUser.role !==
          "superadmin"
        ) {
          if (
            ![
              "teacher",
              "student"
            ].includes(req.body.role)
          ) {
            return res.status(400).json({
              ok: false,
              error:
                "Invalid school user role."
            });
          }
        }

        user.role = req.body.role;
      }

      if (
        req.body.password &&
        req.body.password.length >= 6
      ) {
        user.passwordHash =
          await bcrypt.hash(
            req.body.password,
            12
          );
      }

      if (
        req.body.active !== undefined
      ) {
        user.active =
          Boolean(req.body.active);
      }

      if (
        req.body.profilePicture !==
        undefined
      ) {
        user.profilePicture =
          clean(
            req.body.profilePicture
          );
      }

      user.updatedAt = now();

      users[index] = user;

      saveUsers(users);

      res.json({
        ok: true,
        message:
          "User updated successfully.",
        user: publicUser(user)
      });
    } catch (error) {
      console.error(
        "UPDATE USER ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Could not update user."
      });
    }
  }
);

/* =====================================================
   DELETE USER
===================================================== */

app.delete(
  "/api/users/:id",
  requireSchoolAdmin,
  (req, res) => {
    const users = getUsers();

    const index =
      users.findIndex(
        (user) =>
          user.id === req.params.id
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error: "User not found."
      });
    }

    const user = users[index];

    if (
      user.role === "superadmin"
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Superadmin accounts cannot be deleted here."
      });
    }

    if (
      req.currentUser.role !==
        "superadmin" &&
      user.schoolId !==
        req.currentUser.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "You cannot delete another school's user."
      });
    }

    users.splice(index, 1);

    saveUsers(users);

    res.json({
      ok: true,
      message:
        "User deleted successfully."
    });
  }
);

/* =====================================================
   PROFILE
===================================================== */

app.put(
  "/api/profile",
  requireAuth,
  async (req, res) => {
    try {
      const users = getUsers();

      const index =
        users.findIndex(
          (user) =>
            user.id ===
            req.currentUser.id
        );

      if (index === -1) {
        return res.status(404).json({
          ok: false,
          error: "User not found."
        });
      }

      const user = users[index];

      if (req.body.fullName !== undefined) {
        user.fullName =
          clean(req.body.fullName);
      }

      if (
        req.body.profilePicture !==
        undefined
      ) {
        user.profilePicture =
          clean(
            req.body.profilePicture
          );
      }

      if (
        req.body.password &&
        req.body.password.length >= 6
      ) {
        user.passwordHash =
          await bcrypt.hash(
            req.body.password,
            12
          );
      }

      user.updatedAt = now();

      users[index] = user;

      saveUsers(users);

      res.json({
        ok: true,
        user: publicUser(user)
      });
    } catch (error) {
      console.error(
        "PROFILE ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Profile update failed."
      });
    }
  }
);

/* =====================================================
   SUBJECTS
===================================================== */

app.get(
  "/api/subjects",
  requireAuth,
  (req, res) => {
    let subjects = getSubjects();

    if (
      req.currentUser.role !==
      "superadmin"
    ) {
      subjects =
        subjects.filter(
          (subject) =>
            subject.schoolId ===
            req.currentUser.schoolId
        );
    }

    res.json({
      ok: true,
      subjects
    });
  }
);

app.post(
  "/api/subjects",
  requireSchoolAdmin,
  (req, res) => {
    const {
      name,
      code,
      description
    } = req.body;

    if (!name) {
      return res.status(400).json({
        ok: false,
        error:
          "Subject name is required."
      });
    }

    const schoolId =
      req.currentUser.role ===
      "superadmin"
        ? clean(req.body.schoolId)
        : req.currentUser.schoolId;

    if (!schoolId) {
      return res.status(400).json({
        ok: false,
        error:
          "School ID is required."
      });
    }

    const school =
      getSchoolById(schoolId);

    if (!school) {
      return res.status(404).json({
        ok: false,
        error: "School not found."
      });
    }

    const subjects = getSubjects();

    const subject = {
      id: id("subject"),

      schoolId,

      name: clean(name),

      code: clean(code),

      description:
        clean(description),

      active: true,

      createdAt: now(),

      updatedAt: now()
    };

    subjects.push(subject);

    saveSubjects(subjects);

    res.status(201).json({
      ok: true,
      subject
    });
  }
);

app.delete(
  "/api/subjects/:id",
  requireSchoolAdmin,
  (req, res) => {
    const subjects = getSubjects();

    const index =
      subjects.findIndex(
        (subject) =>
          subject.id ===
          req.params.id
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error: "Subject not found."
      });
    }

    const subject = subjects[index];

    if (
      req.currentUser.role !==
        "superadmin" &&
      subject.schoolId !==
        req.currentUser.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "You cannot delete another school's subject."
      });
    }

    subjects.splice(index, 1);

    saveSubjects(subjects);

    res.json({
      ok: true,
      message:
        "Subject deleted successfully."
    });
  }
);

/* =====================================================
   EXAMS
===================================================== */

app.get(
  "/api/exams",
  requireAuth,
  (req, res) => {
    let exams = getExams();

    if (
      req.currentUser.role !==
      "superadmin"
    ) {
      exams =
        exams.filter(
          (exam) =>
            exam.schoolId ===
            req.currentUser.schoolId
        );
    }

    if (
      req.currentUser.role ===
      "student"
    ) {
      exams = exams.filter(
        (exam) =>
          exam.active !== false
      );
    }

    res.json({
      ok: true,
      exams
    });
  }
);

/* =====================================================
   CREATE EXAM
===================================================== */

app.post(
  "/api/exams",
  requireTeacher,
  (req, res) => {
    const {
      title,
      description,
      subjectId,
      duration,
      totalMarks
    } = req.body;

    if (!title) {
      return res.status(400).json({
        ok: false,
        error:
          "Exam title is required."
      });
    }

    const schoolId =
      req.currentUser.role ===
      "superadmin"
        ? clean(req.body.schoolId)
        : req.currentUser.schoolId;

    if (!schoolId) {
      return res.status(400).json({
        ok: false,
        error:
          "School ID is required."
      });
    }

    const exams = getExams();

    const exam = {
      id: id("exam"),

      schoolId,

      title: clean(title),

      description:
        clean(description),

      subjectId:
        clean(subjectId),

      duration:
        safeNumber(duration, 30),

      totalMarks:
        safeNumber(totalMarks, 0),

      active: true,

      createdBy:
        req.currentUser.id,

      createdAt: now(),

      updatedAt: now()
    };

    exams.push(exam);

    saveExams(exams);

    res.status(201).json({
      ok: true,
      exam
    });
  }
);

/* =====================================================
   UPDATE EXAM
===================================================== */

app.put(
  "/api/exams/:id",
  requireTeacher,
  (req, res) => {
    const exams = getExams();

    const index =
      exams.findIndex(
        (exam) =>
          exam.id ===
          req.params.id
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error: "Exam not found."
      });
    }

    const exam = exams[index];

    if (
      req.currentUser.role !==
        "superadmin" &&
      exam.schoolId !==
        req.currentUser.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "You cannot manage another school's exam."
      });
    }

    if (req.body.title !== undefined) {
      exam.title =
        clean(req.body.title);
    }

    if (
      req.body.description !==
      undefined
    ) {
      exam.description =
        clean(req.body.description);
    }

    if (
      req.body.subjectId !==
      undefined
    ) {
      exam.subjectId =
        clean(req.body.subjectId);
    }

    if (
      req.body.duration !==
      undefined
    ) {
      exam.duration =
        safeNumber(
          req.body.duration,
          exam.duration
        );
    }

    if (
      req.body.totalMarks !==
      undefined
    ) {
      exam.totalMarks =
        safeNumber(
          req.body.totalMarks,
          exam.totalMarks
        );
    }

    if (
      req.body.active !== undefined
    ) {
      exam.active =
        Boolean(req.body.active);
    }

    exam.updatedAt = now();

    exams[index] = exam;

    saveExams(exams);

    res.json({
      ok: true,
      exam
    });
  }
);

/* =====================================================
   QUESTIONS
===================================================== */

app.get(
  "/api/questions",
  requireTeacher,
  (req, res) => {
    let questions =
      getQuestions();

    if (
      req.currentUser.role !==
      "superadmin"
    ) {
      questions =
        questions.filter(
          (question) =>
            question.schoolId ===
            req.currentUser.schoolId
        );
    }

    if (req.query.examId) {
      questions =
        questions.filter(
          (question) =>
            question.examId ===
            req.query.examId
        );
    }

    res.json({
      ok: true,
      questions
    });
  }
);

/* =====================================================
   ADD QUESTION
===================================================== */

app.post(
  "/api/questions",
  requireTeacher,
  (req, res) => {
    const {
      examId,
      question,
      options,
      answer,
      points,
      difficulty,
      tags
    } = req.body;

    if (
      !examId ||
      !question
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "Exam ID and question are required."
      });
    }

    const exams = getExams();

    const exam =
      exams.find(
        (item) =>
          item.id === examId
      );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        error: "Exam not found."
      });
    }

    if (
      req.currentUser.role !==
        "superadmin" &&
      exam.schoolId !==
        req.currentUser.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "You cannot add questions to another school's exam."
      });
    }

    const questions =
      getQuestions();

    const questionRecord = {
      id: id("question"),

      schoolId:
        exam.schoolId,

      examId,

      question:
        clean(question),

      options:
        Array.isArray(options)
          ? options
          : [],

      answer:
        safeNumber(answer, 0),

      points:
        safeNumber(points, 1),

      difficulty:
        clean(difficulty) ||
        "easy",

      tags:
        clean(tags),

      createdBy:
        req.currentUser.id,

      createdAt: now(),

      updatedAt: now()
    };

    questions.push(
      questionRecord
    );

    saveQuestions(questions);

    res.status(201).json({
      ok: true,
      question:
        questionRecord
    });
  }
);

/* =====================================================
   START EXAM
===================================================== */

app.post(
  "/api/exams/:id/start",
  requireAuth,
  (req, res) => {
    if (
      req.currentUser.role !==
      "student"
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Only students can start an exam."
      });
    }

    const exams = getExams();

    const exam =
      exams.find(
        (item) =>
          item.id ===
          req.params.id
      );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        error: "Exam not found."
      });
    }

    if (
      exam.schoolId !==
      req.currentUser.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "This exam does not belong to your school."
      });
    }

    if (exam.active === false) {
      return res.status(400).json({
        ok: false,
        error:
          "This exam is not active."
      });
    }

    const results = getResults();

    const alreadySubmitted =
      results.some(
        (result) =>
          result.examId ===
            exam.id &&
          result.studentId ===
            req.currentUser.id
      );

    if (alreadySubmitted) {
      return res.status(409).json({
        ok: false,
        error:
          "You have already submitted this exam."
      });
    }

    const questions =
      getQuestions()
        .filter(
          (question) =>
            question.examId ===
            exam.id &&
            question.schoolId ===
            req.currentUser.schoolId
        )
        .map(
          ({
            answer,
            ...question
          }) => question
        );

    const startedAt =
      new Date();

    const endsAt =
      new Date(
        startedAt.getTime() +
          safeNumber(
            exam.duration,
            30
          ) *
            60 *
            1000
      );

    const attemptId =
      id("attempt");

    res.json({
      ok: true,

      attempt: {
        id: attemptId,

        examId: exam.id,

        startedAt:
          startedAt.toISOString(),

        endsAt:
          endsAt.toISOString(),

        duration:
          exam.duration
      },

      exam,

      questions
    });
  }
);

/* =====================================================
   SUBMIT EXAM
===================================================== */

app.post(
  "/api/exams/:id/submit",
  requireAuth,
  (req, res) => {
    if (
      req.currentUser.role !==
      "student"
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Only students can submit exams."
      });
    }

    const exams = getExams();

    const exam =
      exams.find(
        (item) =>
          item.id ===
          req.params.id
      );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        error: "Exam not found."
      });
    }

    if (
      exam.schoolId !==
      req.currentUser.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Invalid school exam."
      });
    }

    const results = getResults();

    const existing =
      results.find(
        (result) =>
          result.examId ===
            exam.id &&
          result.studentId ===
            req.currentUser.id
      );

    if (existing) {
      return res.status(409).json({
        ok: false,
        error:
          "This exam has already been submitted."
      });
    }

    const submittedAnswers =
      req.body.answers || {};

    const questions =
      getQuestions().filter(
        (question) =>
          question.examId ===
            exam.id &&
          question.schoolId ===
            req.currentUser.schoolId
      );

    let score = 0;
    let totalMarks = 0;

    questions.forEach(
      (question) => {
        const points =
          safeNumber(
            question.points,
            1
          );

        totalMarks += points;

        const selected =
          submittedAnswers[
            question.id
          ];

        if (
          Number(selected) ===
          Number(question.answer)
        ) {
          score += points;
        }
      }
    );

    const percentage =
      totalMarks > 0
        ? Number(
            (
              (score /
                totalMarks) *
              100
            ).toFixed(2)
          )
        : 0;

    const result = {
      id: id("result"),

      schoolId:
        req.currentUser.schoolId,

      examId: exam.id,

      studentId:
        req.currentUser.id,

      score,

      totalMarks,

      percentage,

      submittedAnswers,

      submittedAt: now()
    };

    results.push(result);

    saveResults(results);

    res.status(201).json({
      ok: true,

      message:
        "Exam submitted successfully.",

      result: {
        id: result.id,

        score,

        totalMarks,

        percentage,

        submittedAt:
          result.submittedAt
      }
    });
  }
);

/* =====================================================
   RESULTS
===================================================== */

app.get(
  "/api/results",
  requireAuth,
  (req, res) => {
    let results =
      getResults();

    if (
      req.currentUser.role ===
      "student"
    ) {
      results =
        results.filter(
          (result) =>
            result.studentId ===
            req.currentUser.id &&
            result.schoolId ===
            req.currentUser.schoolId
        );
    } else if (
      req.currentUser.role !==
      "superadmin"
    ) {
      results =
        results.filter(
          (result) =>
            result.schoolId ===
            req.currentUser.schoolId
        );
    }

    res.json({
      ok: true,
      results
    });
  }
);

/* =====================================================
   ANNOUNCEMENTS
===================================================== */

app.get(
  "/api/announcements",
  requireAuth,
  (req, res) => {
    let announcements =
      getAnnouncements();

    if (
      req.currentUser.role !==
      "superadmin"
    ) {
      announcements =
        announcements.filter(
          (item) =>
            item.schoolId ===
            req.currentUser.schoolId
        );
    }

    announcements.sort(
      (a, b) =>
        new Date(b.createdAt) -
        new Date(a.createdAt)
    );

    res.json({
      ok: true,
      announcements
    });
  }
);

/* =====================================================
   CREATE ANNOUNCEMENT
===================================================== */

app.post(
  "/api/announcements",
  requireSchoolAdmin,
  (req, res) => {
    const {
      title,
      message
    } = req.body;

    if (
      !title ||
      !message
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "Title and message are required."
      });
    }

    const schoolId =
      req.currentUser.role ===
      "superadmin"
        ? clean(req.body.schoolId)
        : req.currentUser.schoolId;

    if (!schoolId) {
      return res.status(400).json({
        ok: false,
        error:
          "School ID is required."
      });
    }

    const school =
      getSchoolById(schoolId);

    if (!school) {
      return res.status(404).json({
        ok: false,
        error: "School not found."
      });
    }

    const announcements =
      getAnnouncements();

    const announcement = {
      id: id("announcement"),

      schoolId,

      title: clean(title),

      message: clean(message),

      createdBy:
        req.currentUser.id,

      createdAt: now(),

      updatedAt: now()
    };

    announcements.push(
      announcement
    );

    saveAnnouncements(
      announcements
    );

    res.status(201).json({
      ok: true,
      announcement
    });
  }
);

/* =====================================================
   ADMIN SUMMARY
===================================================== */

app.get(
  "/api/admin/summary",
  requireSchoolAdmin,
  (req, res) => {
    const users = getUsers();
    const schools = getSchools();
    const subjects = getSubjects();
    const exams = getExams();
    const questions = getQuestions();
    const results = getResults();
    const announcements =
      getAnnouncements();

    if (
      req.currentUser.role ===
      "superadmin"
    ) {
      return res.json({
        ok: true,

        role: "superadmin",

        summary: {
          schools:
            schools.length,

          users:
            users.length,

          schoolAdmins:
            users.filter(
              (user) =>
                user.role ===
                "school_admin"
            ).length,

          teachers:
            users.filter(
              (user) =>
                user.role ===
                "teacher"
            ).length,

          students:
            users.filter(
              (user) =>
                user.role ===
                "student"
            ).length,

          subjects:
            subjects.length,

          exams:
            exams.length,

          questions:
            questions.length,

          results:
            results.length,

          announcements:
            announcements.length
        }
      });
    }

    const schoolId =
      req.currentUser.schoolId;

    res.json({
      ok: true,

      role: "school_admin",

      summary: {
        users:
          users.filter(
            (user) =>
              user.schoolId ===
              schoolId
          ).length,

        teachers:
          users.filter(
            (user) =>
              user.schoolId ===
                schoolId &&
              user.role ===
                "teacher"
          ).length,

        students:
          users.filter(
            (user) =>
              user.schoolId ===
                schoolId &&
              user.role ===
                "student"
          ).length,

        subjects:
          subjects.filter(
            (item) =>
              item.schoolId ===
              schoolId
          ).length,

        exams:
          exams.filter(
            (item) =>
              item.schoolId ===
              schoolId
          ).length,

        questions:
          questions.filter(
            (item) =>
              item.schoolId ===
              schoolId
          ).length,

        results:
          results.filter(
            (item) =>
              item.schoolId ===
              schoolId
          ).length,

        announcements:
          announcements.filter(
            (item) =>
              item.schoolId ===
              schoolId
          ).length
      }
    });
  }
);

/* =====================================================
   TEACHER SUMMARY
===================================================== */

app.get(
  "/api/teacher/summary",
  requireTeacher,
  (req, res) => {
    const schoolId =
      req.currentUser.schoolId;

    const subjects =
      getSubjects().filter(
        (item) =>
          item.schoolId ===
          schoolId
      );

    const exams =
      getExams().filter(
        (item) =>
          item.schoolId ===
          schoolId
      );

    const questions =
      getQuestions().filter(
        (item) =>
          item.schoolId ===
          schoolId
      );

    const results =
      getResults().filter(
        (item) =>
          item.schoolId ===
          schoolId
      );

    res.json({
      ok: true,

      summary: {
        subjects:
          subjects.length,

        exams:
          exams.length,

        questions:
          questions.length,

        results:
          results.length
      }
    });
  }
);

/* =====================================================
   STUDENT SUMMARY
===================================================== */

app.get(
  "/api/student/summary",
  requireAuth,
  (req, res) => {
    if (
      req.currentUser.role !==
      "student"
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Student access required."
      });
    }

    const schoolId =
      req.currentUser.schoolId;

    const exams =
      getExams().filter(
        (exam) =>
          exam.schoolId ===
            schoolId &&
          exam.active !== false
      );

    const results =
      getResults().filter(
        (result) =>
          result.studentId ===
          req.currentUser.id
      );

    const announcements =
      getAnnouncements().filter(
        (item) =>
          item.schoolId ===
          schoolId
      );

    res.json({
      ok: true,

      summary: {
        availableExams:
          exams.length,

        completedExams:
          results.length,

        announcements:
          announcements.length
      },

      recentResults:
        results.slice(-10).reverse(),

      exams:

        exams.slice(0, 10),

      announcements:
        announcements
          .slice(-10)
          .reverse()
    });
  }
);

/* =====================================================
   SUPERADMIN - ALL SCHOOLS
===================================================== */

app.get(
  "/api/admin/schools",
  requireSuperadmin,
  (req, res) => {
    const schools =
      getSchools();

    const users =
      getUsers();

    const enriched =
      schools.map(
        (school) => ({
          ...school,

          userCount:
            users.filter(
              (user) =>
                user.schoolId ===
                school.id
            ).length,

          teacherCount:
            users.filter(
              (user) =>
                user.schoolId ===
                  school.id &&
                user.role ===
                  "teacher"
            ).length,

          studentCount:
            users.filter(
              (user) =>
                user.schoolId ===
                  school.id &&
                user.role ===
                  "student"
            ).length
        })
      );

    res.json({
      ok: true,
      schools: enriched
    });
  }
);

/* =====================================================
   SUPERADMIN - CREATE SCHOOL
===================================================== */

app.post(
  "/api/admin/schools",
  requireSuperadmin,
  (req, res) => {
    const {
      name,
      motto,
      primaryColor,
      secondaryColor,
      theme
    } = req.body;

    if (!name) {
      return res.status(400).json({
        ok: false,
        error:
          "School name is required."
      });
    }

    const schools =
      getSchools();

    const school = {
      id: id("school"),

      name: clean(name),

      motto: clean(motto),

      logo: "",

      primaryColor:
        clean(primaryColor) ||
        "#2563eb",

      secondaryColor:
        clean(secondaryColor) ||
        "#16a34a",

      theme:
        clean(theme) ||
        "light",

      active: true,

      createdAt: now(),

      updatedAt: now()
    };

    schools.push(school);

    saveSchools(schools);

    res.status(201).json({
      ok: true,

      message:
        "School created successfully.",

      school
    });
  }
);

/* =====================================================
   SUPERADMIN - UPDATE SCHOOL
===================================================== */

app.put(
  "/api/admin/schools/:id",
  requireSuperadmin,
  (req, res) => {
    const schools =
      getSchools();

    const index =
      schools.findIndex(
        (school) =>
          school.id ===
          req.params.id
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error: "School not found."
      });
    }

    const school = schools[index];

    if (req.body.name !== undefined) {
      school.name =
        clean(req.body.name);
    }

    if (req.body.motto !== undefined) {
      school.motto =
        clean(req.body.motto);
    }

    if (req.body.logo !== undefined) {
      school.logo =
        clean(req.body.logo);
    }

    if (
      req.body.primaryColor !==
      undefined
    ) {
      school.primaryColor =
        clean(
          req.body.primaryColor
        );
    }

    if (
      req.body.secondaryColor !==
      undefined
    ) {
      school.secondaryColor =
        clean(
          req.body.secondaryColor
        );
    }

    if (req.body.theme !== undefined) {
      school.theme =
        clean(req.body.theme);
    }

    if (
      req.body.active !== undefined
    ) {
      school.active =
        Boolean(req.body.active);
    }

    school.updatedAt = now();

    schools[index] = school;

    saveSchools(schools);

    res.json({
      ok: true,
      school
    });
  }
);

/* =====================================================
   SUPERADMIN - ALL USERS
===================================================== */

app.get(
  "/api/admin/users",
  requireSuperadmin,
  (req, res) => {
    const users =
      getUsers();

    const schools =
      getSchools();

    const output =
      users.map(
        (user) => ({
          ...publicUser(user),

          school:
            schools.find(
              (school) =>
                school.id ===
                user.schoolId
            ) || null
        })
      );

    res.json({
      ok: true,
      users: output
    });
  }
);

/* =====================================================
   SUPERADMIN - PLATFORM SETTINGS
===================================================== */

app.put(
  "/api/admin/settings",
  requireSuperadmin,
  (req, res) => {
    const settings =
      getSettings();

    if (
      req.body.platformName !==
      undefined
    ) {
      settings.platformName =
        clean(
          req.body.platformName
        );
    }

    if (
      req.body.platformDescription !==
      undefined
    ) {
      settings.platformDescription =
        clean(
          req.body.platformDescription
        );
    }

    if (
      req.body.defaultTheme !==
      undefined
    ) {
      settings.defaultTheme =
        clean(
          req.body.defaultTheme
        );
    }

    if (
      req.body.maintenanceMode !==
      undefined
    ) {
      settings.maintenanceMode =
        Boolean(
          req.body.maintenanceMode
        );
    }

    saveSettings(settings);

    res.json({
      ok: true,

      message:
        "Platform settings updated.",

      settings
    });
  }
);

/* =====================================================
   SUPERADMIN - DELETE SCHOOL
===================================================== */

app.delete(
  "/api/admin/schools/:id",
  requireSuperadmin,
  (req, res) => {
    const schoolId =
      req.params.id;

    const schools =
      getSchools();

    const schoolIndex =
      schools.findIndex(
        (school) =>
          school.id === schoolId
      );

    if (schoolIndex === -1) {
      return res.status(404).json({
        ok: false,
        error: "School not found."
      });
    }

    schools.splice(
      schoolIndex,
      1
    );

    saveSchools(schools);

    /*
      Remove all school-owned data.
      Superadmin data remains untouched.
    */

    const users =
      getUsers().filter(
        (user) =>
          user.schoolId !==
          schoolId
      );

    const subjects =
      getSubjects().filter(
        (item) =>
          item.schoolId !==
          schoolId
      );

    const exams =
      getExams().filter(
        (item) =>
          item.schoolId !==
          schoolId
      );

    const questions =
      getQuestions().filter(
        (item) =>
          item.schoolId !==
          schoolId
      );

    const results =
      getResults().filter(
        (item) =>
          item.schoolId !==
          schoolId
      );

    const announcements =
      getAnnouncements().filter(
        (item) =>
          item.schoolId !==
          schoolId
      );

    saveUsers(users);
    saveSubjects(subjects);
    saveExams(exams);
    saveQuestions(questions);
    saveResults(results);
    saveAnnouncements(
      announcements
    );

    res.json({
      ok: true,

      message:
        "School and its school-owned data were deleted."
    });
  }
);

/* =====================================================
   DASHBOARD REDIRECT
===================================================== */

app.get(
  "/dashboard",
  requireAuth,
  (req, res) => {
    res.redirect(
      roleRedirect(
        req.currentUser.role
      )
    );
  }
);

/* =====================================================
   STATIC FRONTEND
===================================================== */

app.use(
  express.static(PUBLIC_DIR)
);

/* =====================================================
   ROOT
===================================================== */

app.get("/", (req, res) => {
  const index =
    path.join(
      PUBLIC_DIR,
      "index.html"
    );

  if (fs.existsSync(index)) {
    return res.sendFile(index);
  }

  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>SchoolHub Pro</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
      </head>
      <body style="font-family:Arial;padding:40px">
        <h1>SchoolHub Pro</h1>
        <p>SchoolHub Pro server is running.</p>
        <p>
          <a href="/login.html">Login</a>
        </p>
      </body>
    </html>
  `);
});

/* =====================================================
   API 404
===================================================== */

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      ok: false,
      error:
        "API endpoint not found."
    });
  }
);

/* =====================================================
   FRONTEND FALLBACK
===================================================== */

app.use(
  (req, res, next) => {
    if (
      req.method !== "GET" ||
      req.path.startsWith("/api/") ||
      req.path.startsWith("/auth/")
    ) {
      return next();
    }

    const requestedFile =
      path.join(
        PUBLIC_DIR,
        req.path
      );

    if (
      fs.existsSync(requestedFile) &&
      fs.statSync(requestedFile).isFile()
    ) {
      return res.sendFile(
        requestedFile
      );
    }

    const index =
      path.join(
        PUBLIC_DIR,
        "index.html"
      );

    if (fs.existsSync(index)) {
      return res.sendFile(index);
    }

    next();
  }
);

/* =====================================================
   ERROR HANDLER
===================================================== */

app.use(
  (error, req, res, next) => {
    console.error(
      "SERVER ERROR:",
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      ok: false,
      error:
        "Internal server error."
    });
  }
);

/* =====================================================
   ENSURE SUPERADMIN
===================================================== */

async function ensureSuperadmin() {
  const email =
    normalizeEmail(
      process.env.SUPERADMIN_EMAIL
    );

  const username =
    normalizeUsername(
      process.env.SUPERADMIN_USERNAME ||
      "superadmin"
    );

  const password =
    process.env.SUPERADMIN_PASSWORD;

  const fullName =
    clean(
      process.env.SUPERADMIN_NAME ||
      "SchoolHub Super Admin"
    );

  if (!email || !password) {
    console.log(
      "Superadmin: NOT CONFIGURED"
    );

    console.log(
      "Set SUPERADMIN_EMAIL and SUPERADMIN_PASSWORD in Railway Variables."
    );

    return;
  }

  if (password.length < 6) {
    console.error(
      "Superadmin password must be at least 6 characters."
    );

    return;
  }

  const users =
    getUsers();

  let user =
    users.find(
      (item) =>
        normalizeEmail(
          item.email
        ) === email
    ) ||
    users.find(
      (item) =>
        normalizeUsername(
          item.username
        ) === username
    );

  if (user) {
    user.role =
      "superadmin";

    user.active = true;

    user.schoolId = null;

    if (!user.username) {
      user.username =
        username;
    }

    if (!user.fullName) {
      user.fullName =
        fullName;
    }

    if (!user.passwordHash) {
      user.passwordHash =
        await bcrypt.hash(
          password,
          12
        );
    }

    user.updatedAt = now();

    saveUsers(users);

    console.log(
      `Superadmin ready: ${user.email}`
    );

    return;
  }

  const passwordHash =
    await bcrypt.hash(
      password,
      12
    );

  user = {
    id: id("user"),

    fullName,

    username,

    email,

    passwordHash,

    role: "superadmin",

    schoolId: null,

    profilePicture: "",

    provider: "local",

    active: true,

    createdAt: now(),

    updatedAt: now()
  };

  users.push(user);

  saveUsers(users);

  console.log(
    `Superadmin created: ${email}`
  );
}

/* =====================================================
   START SERVER
===================================================== */

let httpServer;

async function startServer() {
  try {
    await ensureSuperadmin();

    httpServer =
      app.listen(
        PORT,
        HOST,
        () => {
          console.log("");
          console.log(
            "=========================================="
          );
          console.log(
            "       SCHOOLHUB PRO SERVER"
          );
          console.log(
            "=========================================="
          );
          console.log(
            `Port: ${PORT}`
          );
          console.log(
            `Host: ${HOST}`
          );
          console.log(
            `Environment: ${
              process.env.NODE_ENV ||
              "development"
            }`
          );
          console.log(
            `Storage: ${STORAGE_ROOT}`
          );
          console.log(
            `Google Auth: ${
              googleConfigured
                ? "CONFIGURED"
                : "NOT CONFIGURED"
            }`
          );
          console.log(
            "Roles: superadmin, school_admin, teacher, student"
          );
          console.log(
            "=========================================="
          );
          console.log("");
        }
      );
  } catch (error) {
    console.error(
      "STARTUP ERROR:",
      error
    );

    process.exit(1);
  }
}

/* =====================================================
   GRACEFUL SHUTDOWN
===================================================== */

function shutdown(signal) {
  console.log(
    `${signal} received. Shutting down...`
  );

  if (!httpServer) {
    process.exit(0);
  }

  httpServer.close(() => {
    console.log(
      "SchoolHub Pro server stopped."
    );

    process.exit(0);
  });

  setTimeout(() => {
    console.error(
      "Forced shutdown."
    );

    process.exit(1);
  }, 10000).unref();
}

process.on(
  "SIGTERM",
  () => shutdown("SIGTERM")
);

process.on(
  "SIGINT",
  () => shutdown("SIGINT")
);

process.on(
  "uncaughtException",
  (error) => {
    console.error(
      "UNCAUGHT EXCEPTION:",
      error
    );
  }
);

process.on(
  "unhandledRejection",
  (reason) => {
    console.error(
      "UNHANDLED REJECTION:",
      reason
    );
  }
);

/* =====================================================
   START
===================================================== */

startServer();
