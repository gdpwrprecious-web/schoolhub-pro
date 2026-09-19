// ============================================================
// SCHOOLHUB PRO
// MULTI-SCHOOL SCHOOL MANAGEMENT + CBT PLATFORM
// FULL SERVER
// Version 6.0.0
// ============================================================

"use strict";

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");

dotenv.config();

// ============================================================
// APP CONFIG
// ============================================================

const app = express();

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";

const IS_PRODUCTION =
  String(process.env.NODE_ENV || "").toLowerCase() === "production";

const PUBLIC_DIR = path.join(__dirname, "public");

const STORAGE_ROOT =
  process.env.STORAGE_ROOT ||
  path.join(__dirname, "storage");

const DATA_DIR = path.join(STORAGE_ROOT, "data");
const UPLOAD_DIR = path.join(STORAGE_ROOT, "uploads");
const PROFILE_UPLOAD_DIR = path.join(UPLOAD_DIR, "profiles");
const BRANDING_UPLOAD_DIR = path.join(UPLOAD_DIR, "branding");

const USERS_FILE = path.join(DATA_DIR, "users.json");
const SCHOOLS_FILE = path.join(DATA_DIR, "schools.json");
const SETTINGS_FILE = path.join(DATA_DIR, "settings.json");
const SUBJECTS_FILE = path.join(DATA_DIR, "subjects.json");
const EXAMS_FILE = path.join(DATA_DIR, "exams.json");
const QUESTIONS_FILE = path.join(DATA_DIR, "questions.json");
const RESULTS_FILE = path.join(DATA_DIR, "results.json");
const ANNOUNCEMENTS_FILE = path.join(DATA_DIR, "announcements.json");

const SESSION_FILE = path.join(STORAGE_ROOT, "sessions.json");

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "schoolhub-development-secret-change-this-in-production";


// ============================================================
// CREATE DIRECTORIES
// ============================================================

[
  STORAGE_ROOT,
  DATA_DIR,
  UPLOAD_DIR,
  PROFILE_UPLOAD_DIR,
  BRANDING_UPLOAD_DIR,
  PUBLIC_DIR
].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});


// ============================================================
// JSON HELPERS
// ============================================================

function readJSON(file, fallback) {
  try {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(
        file,
        JSON.stringify(fallback, null, 2),
        "utf8"
      );

      return fallback;
    }

    const raw = fs.readFileSync(file, "utf8").trim();

    if (!raw) {
      fs.writeFileSync(
        file,
        JSON.stringify(fallback, null, 2),
        "utf8"
      );

      return fallback;
    }

    const parsed = JSON.parse(raw);

    return parsed;
  } catch (error) {
    console.error(`Failed reading ${file}:`, error.message);

    return fallback;
  }
}

function saveJSON(file, data) {
  const tempFile = `${file}.tmp`;

  try {
    fs.writeFileSync(
      tempFile,
      JSON.stringify(data, null, 2),
      "utf8"
    );

    fs.renameSync(tempFile, file);

    return true;
  } catch (error) {
    console.error(`Failed saving ${file}:`, error.message);

    try {
      if (fs.existsSync(tempFile)) {
        fs.unlinkSync(tempFile);
      }
    } catch (_) {}

    return false;
  }
}


// ============================================================
// DEFAULT DATA
// ============================================================

const DEFAULT_SETTINGS = {
  platformName: "SchoolHub Pro",
  platformDescription:
    "Smart school management for modern schools.",
  defaultTheme: "light",
  maintenanceMode: false,
  updatedAt: new Date().toISOString()
};


// ============================================================
// LOAD DATABASE
// ============================================================

let users = readJSON(USERS_FILE, []);
let schools = readJSON(SCHOOLS_FILE, []);
let settings = readJSON(SETTINGS_FILE, DEFAULT_SETTINGS);

let subjects = readJSON(SUBJECTS_FILE, []);
let exams = readJSON(EXAMS_FILE, []);
let questions = readJSON(QUESTIONS_FILE, []);
let results = readJSON(RESULTS_FILE, []);
let announcements = readJSON(ANNOUNCEMENTS_FILE, []);


// ============================================================
// NORMALIZE DATA
// ============================================================

if (!Array.isArray(users)) users = [];
if (!Array.isArray(schools)) schools = [];
if (!Array.isArray(subjects)) subjects = [];
if (!Array.isArray(exams)) exams = [];
if (!Array.isArray(questions)) questions = [];
if (!Array.isArray(results)) results = [];
if (!Array.isArray(announcements)) announcements = [];

if (!settings || typeof settings !== "object") {
  settings = DEFAULT_SETTINGS;
}

if (!settings.platformName) {
  settings.platformName = "SchoolHub Pro";
}

if (!settings.platformDescription) {
  settings.platformDescription =
    "Smart school management for modern schools.";
}

saveJSON(USERS_FILE, users);
saveJSON(SCHOOLS_FILE, schools);
saveJSON(SETTINGS_FILE, settings);
saveJSON(SUBJECTS_FILE, subjects);
saveJSON(EXAMS_FILE, exams);
saveJSON(QUESTIONS_FILE, questions);
saveJSON(RESULTS_FILE, results);
saveJSON(ANNOUNCEMENTS_FILE, announcements);


// ============================================================
// BASIC HELPERS
// ============================================================

function now() {
  return new Date().toISOString();
}

function id(prefix = "id") {
  return `${prefix}_${Date.now()}_${crypto
    .randomBytes(6)
    .toString("hex")}`;
}

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function normalizeUsername(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function cleanString(value, fallback = "") {
  if (value === undefined || value === null) {
    return fallback;
  }

  return String(value).trim();
}

function isValidRole(role) {
  return [
    "superadmin",
    "school_admin",
    "teacher",
    "student"
  ].includes(role);
}

function isSchoolRole(role) {
  return [
    "school_admin",
    "teacher",
    "student"
  ].includes(role);
}

function safeUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    fullName: user.fullName || "",
    username: user.username || "",
    email: user.email || "",
    role: user.role || "",
    schoolId: user.schoolId || null,
    profilePicture: user.profilePicture || "",
    provider: user.provider || "local",
    active: user.active !== false,
    createdAt: user.createdAt || null,
    updatedAt: user.updatedAt || null
  };
}

function safeQuestion(question, includeAnswer = true) {
  if (!question) return null;

  const output = {
    id: question.id,
    schoolId: question.schoolId,
    subjectId: question.subjectId || null,
    examId: question.examId || null,
    question: question.question || "",
    options: Array.isArray(question.options)
      ? question.options
      : [],
    points: Number(question.points || 1),
    difficulty: question.difficulty || "medium",
    tags: question.tags || "",
    active: question.active !== false,
    createdBy: question.createdBy || null,
    createdAt: question.createdAt || null,
    updatedAt: question.updatedAt || null
  };

  if (includeAnswer) {
    output.answer = Number(question.answer || 0);
  }

  return output;
}

function safeSchool(school) {
  if (!school) return null;

  return {
    id: school.id,
    name: school.name || "",
    motto: school.motto || "",
    logo: school.logo || "",
    primaryColor: school.primaryColor || "#2563eb",
    secondaryColor: school.secondaryColor || "#16a34a",
    theme: school.theme || "light",
    active: school.active !== false,
    createdAt: school.createdAt || null,
    updatedAt: school.updatedAt || null
  };
}

function roleRedirect(user) {
  if (!user) return "/login.html";

  if (user.role === "superadmin") {
    return "/superadmin.html";
  }

  if (user.role === "school_admin") {
    return "/admin.html";
  }

  if (user.role === "teacher") {
    return "/teacher.html";
  }

  if (user.role === "student") {
    return "/student.html";
  }

  return "/login.html";
}

function getSchoolForUser(user) {
  if (!user || !user.schoolId) {
    return null;
  }

  return schools.find(
    school => String(school.id) === String(user.schoolId)
  ) || null;
}

function sameSchool(user, schoolId) {
  if (!user) return false;

  if (user.role === "superadmin") {
    return true;
  }

  return String(user.schoolId) === String(schoolId);
}

function canManageSchool(user, schoolId) {
  if (!user) return false;

  if (user.role === "superadmin") {
    return true;
  }

  if (
    user.role === "school_admin" &&
    String(user.schoolId) === String(schoolId)
  ) {
    return true;
  }

  return false;
}

function isAdmin(user) {
  return (
    user &&
    [
      "superadmin",
      "school_admin"
    ].includes(user.role)
  );
}

function isStaff(user) {
  return (
    user &&
    [
      "superadmin",
      "school_admin",
      "teacher"
    ].includes(user.role)
  );
}


// ============================================================
// EXPRESS CONFIGURATION
// ============================================================

app.disable("x-powered-by");

if (IS_PRODUCTION) {
  app.set("trust proxy", 1);
}

app.use(express.json({ limit: "10mb" }));

app.use(
  express.urlencoded({
    extended: true,
    limit: "10mb"
  })
);


// ============================================================
// FILE-BACKED SESSION STORE
// Prevents session loss on Railway restarts.
// ============================================================

class FileSessionStore extends session.Store {
  constructor(file) {
    super();

    this.file = file;
    this.sessions = {};

    this.load();
  }

  load() {
    try {
      if (!fs.existsSync(this.file)) {
        this.sessions = {};
        this.save();
        return;
      }

      const raw = fs.readFileSync(this.file, "utf8").trim();

      if (!raw) {
        this.sessions = {};
        return;
      }

      this.sessions = JSON.parse(raw);

      if (
        !this.sessions ||
        typeof this.sessions !== "object" ||
        Array.isArray(this.sessions)
      ) {
        this.sessions = {};
      }
    } catch (error) {
      console.error(
        "Session store load error:",
        error.message
      );

      this.sessions = {};
    }
  }

  save() {
    try {
      const temp = `${this.file}.tmp`;

      fs.writeFileSync(
        temp,
        JSON.stringify(this.sessions, null, 2),
        "utf8"
      );

      fs.renameSync(temp, this.file);
    } catch (error) {
      console.error(
        "Session store save error:",
        error.message
      );
    }
  }

  cleanup() {
    const current = Date.now();

    for (const sid of Object.keys(this.sessions)) {
      const sessionData = this.sessions[sid];

      if (
        sessionData &&
        sessionData.cookie &&
        sessionData.cookie.expires
      ) {
        const expiry = new Date(
          sessionData.cookie.expires
        ).getTime();

        if (
          Number.isFinite(expiry) &&
          expiry <= current
        ) {
          delete this.sessions[sid];
        }
      }
    }

    this.save();
  }

  get(sid, callback) {
    try {
      const data = this.sessions[sid];

      if (!data) {
        return callback(null, null);
      }

      if (
        data.cookie &&
        data.cookie.expires
      ) {
        const expiry = new Date(
          data.cookie.expires
        ).getTime();

        if (
          Number.isFinite(expiry) &&
          expiry <= Date.now()
        ) {
          delete this.sessions[sid];
          this.save();

          return callback(null, null);
        }
      }

      if (
        data.cookie &&
        data.cookie.expires
      ) {
        data.cookie.expires = new Date(
          data.cookie.expires
        );
      }

      callback(null, data);
    } catch (error) {
      callback(error);
    }
  }

  set(sid, sessionData, callback) {
    try {
      this.sessions[sid] = sessionData;
      this.save();

      callback(null);
    } catch (error) {
      callback(error);
    }
  }

  destroy(sid, callback) {
    try {
      delete this.sessions[sid];
      this.save();

      callback(null);
    } catch (error) {
      callback(error);
    }
  }

  touch(sid, sessionData, callback) {
    try {
      if (this.sessions[sid]) {
        this.sessions[sid].cookie =
          sessionData.cookie;

        this.save();
      }

      callback(null);
    } catch (error) {
      callback(error);
    }
  }
}

const sessionStore =
  new FileSessionStore(SESSION_FILE);

sessionStore.cleanup();


// ============================================================
// SESSION
// ============================================================

app.use(
  session({
    store: sessionStore,

    secret: SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    rolling: true,

    proxy: IS_PRODUCTION,

    cookie: {
      httpOnly: true,

      secure: IS_PRODUCTION,

      sameSite: "lax",

      maxAge:
        1000 *
        60 *
        60 *
        24 *
        7
    }
  })
);


// ============================================================
// PASSPORT
// ============================================================

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((userId, done) => {
  try {
    const user = users.find(
      u => String(u.id) === String(userId)
    );

    if (!user) {
      return done(null, false);
    }

    if (user.active === false) {
      return done(null, false);
    }

    done(null, user);
  } catch (error) {
    done(error);
  }
});


// ============================================================
// GOOGLE AUTH
// ============================================================

const GOOGLE_CLIENT_ID =
  process.env.GOOGLE_CLIENT_ID || "";

const GOOGLE_CLIENT_SECRET =
  process.env.GOOGLE_CLIENT_SECRET || "";

const GOOGLE_CALLBACK_URL =
  process.env.GOOGLE_CALLBACK_URL || "";

const googleConfigured =
  Boolean(
    GOOGLE_CLIENT_ID &&
    GOOGLE_CLIENT_SECRET &&
    GOOGLE_CALLBACK_URL
  );

if (googleConfigured) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: GOOGLE_CALLBACK_URL
      },

      async (
        accessToken,
        refreshToken,
        profile,
        done
      ) => {
        try {
          const email =
            normalizeEmail(
              profile.emails?.[0]?.value || ""
            );

          const googleId =
            profile.id;

          let user = users.find(
            u =>
              String(u.googleId || "") ===
              String(googleId)
          );

          if (!user && email) {
            user = users.find(
              u =>
                normalizeEmail(u.email) ===
                email
            );
          }

          if (!user) {
            return done(
              null,
              false,
              {
                message:
                  "Google account is not registered. Create a SchoolHub account first."
              }
            );
          }

          if (user.active === false) {
            return done(
              null,
              false,
              {
                message:
                  "This account has been disabled."
              }
            );
          }

          let changed = false;

          if (!user.googleId) {
            user.googleId = googleId;
            changed = true;
          }

          if (
            profile.photos &&
            profile.photos[0] &&
            !user.profilePicture
          ) {
            user.profilePicture =
              profile.photos[0].value || "";

            changed = true;
          }

          user.provider = "google";
          user.updatedAt = now();

          changed = true;

          if (changed) {
            saveJSON(USERS_FILE, users);
          }

          done(null, user);
        } catch (error) {
          done(error);
        }
      }
    )
  );
}

console.log(
  `Google Auth: ${
    googleConfigured
      ? "CONFIGURED"
      : "NOT CONFIGURED"
  }`
);


// ============================================================
// MULTER IMAGE UPLOADS
// ============================================================

const imageStorage =
  multer.diskStorage({
    destination: (req, file, callback) => {
      const isBranding =
        req.originalUrl.includes(
          "/school/branding"
        );

      callback(
        null,
        isBranding
          ? BRANDING_UPLOAD_DIR
          : PROFILE_UPLOAD_DIR
      );
    },

    filename: (req, file, callback) => {
      const extension =
        path.extname(
          file.originalname || ""
        ).toLowerCase();

      const filename =
        `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${extension}`;

      callback(null, filename);
    }
  });

const upload =
  multer({
    storage: imageStorage,

    limits: {
      fileSize:
        5 * 1024 * 1024
    },

    fileFilter: (
      req,
      file,
      callback
    ) => {
      const allowed = [
        "image/jpeg",
        "image/png",
        "image/webp",
        "image/gif"
      ];

      if (
        allowed.includes(file.mimetype)
      ) {
        callback(null, true);
      } else {
        callback(
          new Error(
            "Only JPG, PNG, WEBP and GIF images are allowed."
          )
        );
      }
    }
  });


// ============================================================
// STATIC UPLOADS
// ============================================================

app.use(
  "/uploads",
  express.static(UPLOAD_DIR)
);


// ============================================================
// AUTH MIDDLEWARE
// ============================================================

function requireAuth(req, res, next) {
  if (
    req.isAuthenticated &&
    req.isAuthenticated() &&
    req.user
  ) {
    return next();
  }

  return res.status(401).json({
    ok: false,
    error: "Authentication required",
    code: "AUTH_REQUIRED"
  });
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (
      !req.user ||
      !roles.includes(req.user.role)
    ) {
      return res.status(403).json({
        ok: false,
        error: "You do not have permission to perform this action."
      });
    }

    next();
  };
}


// ============================================================
// HEALTH
// ============================================================

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
        : "NOT CONFIGURED",
    time: now()
  });
});


// ============================================================
// PLATFORM
// ============================================================

app.get("/api/platform", (req, res) => {
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
        settings.maintenanceMode === true
    }
  });
});

app.get("/api/platform-config", (req, res) => {
  res.json({
    ok: true,

    platformName:
      settings.platformName ||
      "SchoolHub Pro",

    platformDescription:
      settings.platformDescription ||
      "",

    defaultTheme:
      settings.defaultTheme ||
      "light",

    maintenanceMode:
      settings.maintenanceMode === true
  });
});


// ============================================================
// CURRENT USER
// ============================================================

app.get(
  "/api/me",
  requireAuth,
  (req, res) => {
    const freshUser =
      users.find(
        u =>
          String(u.id) ===
          String(req.user.id)
      );

    if (!freshUser) {
      return res.status(401).json({
        ok: false,
        error: "User account no longer exists."
      });
    }

    const school =
      getSchoolForUser(freshUser);

    res.json({
      ok: true,
      user: safeUser(freshUser),
      school: safeSchool(school),
      redirect: roleRedirect(freshUser)
    });
  }
);


// ============================================================
// REGISTER
// ============================================================

app.post(
  "/api/register",
  async (req, res) => {
    try {
      const {
        schoolName,
        schoolMotto,
        fullName,
        username,
        email,
        password,
        confirmPassword
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

      if (
        confirmPassword !== undefined &&
        password !== confirmPassword
      ) {
        return res.status(400).json({
          ok: false,
          error: "Passwords do not match."
        });
      }

      if (String(password).length < 6) {
        return res.status(400).json({
          ok: false,
          error:
            "Password must be at least 6 characters."
        });
      }

      const cleanEmail =
        normalizeEmail(email);

      const cleanUsername =
        normalizeUsername(username);

      if (
        users.some(
          u =>
            normalizeEmail(u.email) ===
            cleanEmail
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
          u =>
            normalizeUsername(
              u.username
            ) === cleanUsername
        )
      ) {
        return res.status(409).json({
          ok: false,
          error:
            "That username is already in use."
        });
      }

      const school = {
        id: id("school"),

        name:
          cleanString(schoolName),

        motto:
          cleanString(schoolMotto),

        logo: "",

        primaryColor:
          "#2563eb",

        secondaryColor:
          "#16a34a",

        theme: "light",

        active: true,

        createdAt: now(),

        updatedAt: now()
      };

      const passwordHash =
        await bcrypt.hash(
          String(password),
          12
        );

      const user = {
        id: id("user"),

        fullName:
          cleanString(fullName),

        username:
          cleanUsername,

        email:
          cleanEmail,

        passwordHash,

        role: "school_admin",

        schoolId: school.id,

        profilePicture: "",

        provider: "local",

        googleId: "",

        active: true,

        createdAt: now(),

        updatedAt: now()
      };

      schools.push(school);
      users.push(user);

      saveJSON(
        SCHOOLS_FILE,
        schools
      );

      saveJSON(
        USERS_FILE,
        users
      );

      req.login(
        user,
        loginError => {
          if (loginError) {
            console.error(
              "Registration login error:",
              loginError
            );

            return res.status(500).json({
              ok: false,
              error:
                "Account created but automatic login failed."
            });
          }

          req.session.save(
            sessionError => {
              if (sessionError) {
                console.error(
                  "Registration session save error:",
                  sessionError
                );

                return res.status(500).json({
                  ok: false,
                  error:
                    "Account created but session could not be saved."
                });
              }

              return res.status(201).json({
                ok: true,
                message:
                  "School account created successfully.",
                user: safeUser(user),
                school:
                  safeSchool(school),
                redirect:
                  "/admin.html"
              });
            }
          );
        }
      );
    } catch (error) {
      console.error(
        "Register error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to create account."
      });
    }
  }
);


// Alias
app.post(
  "/api/signup",
  (req, res, next) => {
    req.url = "/api/register";
    next();
  }
);


// ============================================================
// LOGIN
// ============================================================

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const {
        email,
        username,
        password
      } = req.body;

      const identifier =
        normalizeEmail(
          email || username
        );

      if (
        !identifier ||
        !password
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Username/email and password are required."
        });
      }

      const user =
        users.find(
          u =>
            normalizeEmail(
              u.email
            ) === identifier ||
            normalizeUsername(
              u.username
            ) === identifier
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
            "This account does not have a local password. Use Google Sign-In if configured."
        });
      }

      const valid =
        await bcrypt.compare(
          String(password),
          user.passwordHash
        );

      if (!valid) {
        return res.status(401).json({
          ok: false,
          error:
            "Invalid username/email or password."
        });
      }

      req.login(
        user,
        loginError => {
          if (loginError) {
            console.error(
              "Login error:",
              loginError
            );

            return res.status(500).json({
              ok: false,
              error:
                "An internal error occurred during login."
            });
          }

          req.session.save(
            sessionError => {
              if (sessionError) {
                console.error(
                  "Session save error:",
                  sessionError
                );

                return res.status(500).json({
                  ok: false,
                  error:
                    "Login session could not be saved."
                });
              }

              res.json({
                ok: true,
                message:
                  "Login successful.",
                user:
                  safeUser(user),
                redirect:
                  roleRedirect(user)
              });
            }
          );
        }
      );
    } catch (error) {
      console.error(
        "Login error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "An internal error occurred during login."
      });
    }
  }
);


// ============================================================
// LOGOUT
// ============================================================

app.post(
  "/api/logout",
  (req, res) => {
    req.logout(error => {
      if (error) {
        console.error(
          "Logout error:",
          error
        );

        return res.status(500).json({
          ok: false,
          error:
            "Logout failed."
        });
      }

      req.session.destroy(
        sessionError => {
          if (sessionError) {
            console.error(
              "Session destroy error:",
              sessionError
            );
          }

          res.clearCookie(
            "connect.sid",
            {
              httpOnly: true,
              secure: IS_PRODUCTION,
              sameSite: "lax"
            }
          );

          res.json({
            ok: true,
            message:
              "Logged out successfully."
          });
        }
      );
    });
  }
);


// ============================================================
// GOOGLE LOGIN
// ============================================================

app.get(
  "/auth/google",
  (req, res, next) => {
    if (!googleConfigured) {
      return res.redirect(
        "/login.html?error=google_not_configured"
      );
    }

    passport.authenticate(
      "google",
      {
        scope: [
          "profile",
          "email"
        ],

        prompt: "select_account"
      }
    )(req, res, next);
  }
);


// ============================================================
// GOOGLE CALLBACK
// ============================================================

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
      (
        error,
        user,
        info
      ) => {
        if (error) {
          console.error(
            "Google authentication error:",
            error
          );

          return res.redirect(
            "/login.html?error=google_failed"
          );
        }

        if (!user) {
          const message =
            info?.message ||
            "google_account_not_registered";

          return res.redirect(
            `/login.html?error=${encodeURIComponent(
              message
            )}`
          );
        }

        req.logIn(
          user,
          loginError => {
            if (loginError) {
              console.error(
                "Google session login error:",
                loginError
              );

              return res.redirect(
                "/login.html?error=google_session_failed"
              );
            }

            req.session.save(
              sessionError => {
                if (sessionError) {
                  console.error(
                    "Google session save error:",
                    sessionError
                  );

                  return res.redirect(
                    "/login.html?error=session_failed"
                  );
                }

                return res.redirect(
                  roleRedirect(user)
                );
              }
            );
          }
        );
      }
    )(req, res, next);
  }
);


// ============================================================
// PROFILE
// ============================================================

app.put(
  "/api/profile",
  requireAuth,
  async (req, res) => {
    try {
      const user =
        users.find(
          u =>
            String(u.id) ===
            String(req.user.id)
        );

      if (!user) {
        return res.status(404).json({
          ok: false,
          error:
            "User not found."
        });
      }

      const {
        fullName,
        username,
        password
      } = req.body;

      if (fullName !== undefined) {
        user.fullName =
          cleanString(fullName);
      }

      if (username !== undefined) {
        const newUsername =
          normalizeUsername(username);

        const existing =
          users.find(
            u =>
              String(u.id) !==
                String(user.id) &&
              normalizeUsername(
                u.username
              ) === newUsername
          );

        if (existing) {
          return res.status(409).json({
            ok: false,
            error:
              "That username is already in use."
          });
        }

        user.username =
          newUsername;
      }

      if (
        password !== undefined &&
        String(password).length > 0
      ) {
        if (
          String(password).length < 6
        ) {
          return res.status(400).json({
            ok: false,
            error:
              "Password must be at least 6 characters."
          });
        }

        user.passwordHash =
          await bcrypt.hash(
            String(password),
            12
          );
      }

      user.updatedAt = now();

      saveJSON(
        USERS_FILE,
        users
      );

      res.json({
        ok: true,
        user: safeUser(user)
      });
    } catch (error) {
      console.error(
        "Profile update error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to update profile."
      });
    }
  }
);


// ============================================================
// PROFILE PICTURE
// ============================================================

app.post(
  "/api/profile/picture",
  requireAuth,
  upload.single("profilePicture"),
  (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          ok: false,
          error:
            "Please select an image."
        });
      }

      const user =
        users.find(
          u =>
            String(u.id) ===
            String(req.user.id)
        );

      if (!user) {
        return res.status(404).json({
          ok: false,
          error:
            "User not found."
        });
      }

      if (
        user.profilePicture &&
        user.profilePicture.startsWith(
          "/uploads/"
        )
      ) {
        const oldPath =
          path.join(
            STORAGE_ROOT,
            user.profilePicture
              .replace(
                /^\/uploads\//,
                "uploads/"
              )
          );

        try {
          if (fs.existsSync(oldPath)) {
            fs.unlinkSync(oldPath);
          }
        } catch (_) {}
      }

      user.profilePicture =
        `/uploads/profiles/${req.file.filename}`;

      user.updatedAt = now();

      saveJSON(
        USERS_FILE,
        users
      );

      res.json({
        ok: true,
        message:
          "Profile picture updated.",
        profilePicture:
          user.profilePicture,
        user:
          safeUser(user)
      });
    } catch (error) {
      console.error(
        "Profile picture error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to upload profile picture."
      });
    }
  }
);


// ============================================================
// SCHOOL
// ============================================================

app.get(
  "/api/school",
  requireAuth,
  (req, res) => {
    if (req.user.role === "superadmin") {
      return res.json({
        ok: true,
        school: null,
        schools:
          schools.map(safeSchool)
      });
    }

    const school =
      getSchoolForUser(req.user);

    if (!school) {
      return res.status(404).json({
        ok: false,
        error:
          "School not found."
      });
    }

    res.json({
      ok: true,
      school:
        safeSchool(school)
    });
  }
);


// Alias commonly used by dashboards
app.get(
  "/api/school/branding",
  requireAuth,
  (req, res) => {
    if (req.user.role === "superadmin") {
      return res.json({
        ok: true,
        school: null
      });
    }

    const school =
      getSchoolForUser(req.user);

    if (!school) {
      return res.status(404).json({
        ok: false,
        error:
          "School not found."
      });
    }

    res.json({
      ok: true,
      branding: {
        name: school.name,
        motto: school.motto,
        logo: school.logo,
        primaryColor:
          school.primaryColor,
        secondaryColor:
          school.secondaryColor,
        theme:
          school.theme
      },

      school:
        safeSchool(school)
    });
  }
);


// ============================================================
// SCHOOL BRANDING UPDATE
// ============================================================

app.put(
  "/api/school/branding",
  requireAuth,
  requireRole(
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    try {
      let school;

      if (
        req.user.role === "superadmin" &&
        req.body.schoolId
      ) {
        school =
          schools.find(
            s =>
              String(s.id) ===
              String(
                req.body.schoolId
              )
          );
      } else {
        school =
          getSchoolForUser(req.user);
      }

      if (!school) {
        return res.status(404).json({
          ok: false,
          error:
            "School not found."
        });
      }

      if (
        req.user.role !== "superadmin" &&
        school.id !== req.user.schoolId
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "You cannot edit another school."
        });
      }

      if (
        req.body.name !== undefined
      ) {
        school.name =
          cleanString(req.body.name);
      }

      if (
        req.body.motto !== undefined
      ) {
        school.motto =
          cleanString(req.body.motto);
      }

      if (
        req.body.primaryColor !==
        undefined
      ) {
        school.primaryColor =
          cleanString(
            req.body.primaryColor,
            "#2563eb"
          );
      }

      if (
        req.body.secondaryColor !==
        undefined
      ) {
        school.secondaryColor =
          cleanString(
            req.body.secondaryColor,
            "#16a34a"
          );
      }

      if (
        req.body.theme !== undefined
      ) {
        school.theme =
          ["light", "dark"].includes(
            String(req.body.theme)
          )
            ? String(req.body.theme)
            : school.theme;
      }

      school.updatedAt = now();

      saveJSON(
        SCHOOLS_FILE,
        schools
      );

      res.json({
        ok: true,
        school:
          safeSchool(school)
      });
    } catch (error) {
      console.error(
        "Branding update error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to update school branding."
      });
    }
  }
);


// ============================================================
// SCHOOL LOGO UPLOAD
// ============================================================

app.post(
  "/api/school/branding/logo",
  requireAuth,
  requireRole(
    "school_admin",
    "superadmin"
  ),
  upload.single("logo"),
  (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          ok: false,
          error:
            "Please select a logo image."
        });
      }

      let school;

      if (
        req.user.role === "superadmin" &&
        req.body.schoolId
      ) {
        school =
          schools.find(
            s =>
              String(s.id) ===
              String(
                req.body.schoolId
              )
          );
      } else {
        school =
          getSchoolForUser(req.user);
      }

      if (!school) {
        return res.status(404).json({
          ok: false,
          error:
            "School not found."
        });
      }

      if (
        school.logo &&
        school.logo.startsWith(
          "/uploads/"
        )
      ) {
        const oldPath =
          path.join(
            STORAGE_ROOT,
            school.logo.replace(
              /^\/uploads\//,
              "uploads/"
            )
          );

        try {
          if (fs.existsSync(oldPath)) {
            fs.unlinkSync(oldPath);
          }
        } catch (_) {}
      }

      school.logo =
        `/uploads/branding/${req.file.filename}`;

      school.updatedAt = now();

      saveJSON(
        SCHOOLS_FILE,
        schools
      );

      res.json({
        ok: true,
        message:
          "School logo updated.",
        logo:
          school.logo,
        school:
          safeSchool(school)
      });
    } catch (error) {
      console.error(
        "School logo error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to upload school logo."
      });
    }
  }
);


// ============================================================
// USERS
// ============================================================

app.get(
  "/api/users",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin"
  ),
  (req, res) => {
    let list =
      users.slice();

    if (
      req.user.role !==
      "superadmin"
    ) {
      list =
        list.filter(
          u =>
            String(u.schoolId) ===
            String(
              req.user.schoolId
            )
        );
    }

    res.json({
      ok: true,
      count: list.length,
      users:
        list.map(safeUser)
    });
  }
);


// ============================================================
// CREATE USER
// ============================================================

app.post(
  "/api/users",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin"
  ),
  async (req, res) => {
    try {
      const {
        fullName,
        username,
        email,
        password
      } = req.body;

      let role =
        req.body.role || "student";

      if (!fullName ||
          !username ||
          !email ||
          !password) {
        return res.status(400).json({
          ok: false,
          error:
            "Full name, username, email and password are required."
        });
      }

      if (!isValidRole(role)) {
        return res.status(400).json({
          ok: false,
          error:
            "Invalid user role."
        });
      }

      // School admins can only create
      // teachers and students.
      if (
        req.user.role ===
        "school_admin"
      ) {
        if (
          ![
            "teacher",
            "student"
          ].includes(role)
        ) {
          return res.status(403).json({
            ok: false,
            error:
              "School admins can create teachers and students only."
          });
        }
      }

      let schoolId =
        req.body.schoolId ||
        req.user.schoolId ||
        null;

      if (
        role !== "superadmin" &&
        !schoolId
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "A school is required."
        });
      }

      if (
        req.user.role ===
        "school_admin"
      ) {
        schoolId =
          req.user.schoolId;
      }

      if (
        schoolId &&
        !schools.some(
          s =>
            String(s.id) ===
            String(schoolId)
        )
      ) {
        return res.status(404).json({
          ok: false,
          error:
            "School not found."
        });
      }

      const cleanEmail =
        normalizeEmail(email);

      const cleanUsername =
        normalizeUsername(username);

      if (
        users.some(
          u =>
            normalizeEmail(
              u.email
            ) === cleanEmail
        )
      ) {
        return res.status(409).json({
          ok: false,
          error:
            "Email is already in use."
        });
      }

      if (
        users.some(
          u =>
            normalizeUsername(
              u.username
            ) === cleanUsername
        )
      ) {
        return res.status(409).json({
          ok: false,
          error:
            "Username is already in use."
        });
      }

      const newUser = {
        id: id("user"),

        fullName:
          cleanString(fullName),

        username:
          cleanUsername,

        email:
          cleanEmail,

        passwordHash:
          await bcrypt.hash(
            String(password),
            12
          ),

        role,

        schoolId,

        profilePicture: "",

        provider: "local",

        googleId: "",

        active: true,

        createdAt: now(),

        updatedAt: now()
      };

      users.push(newUser);

      saveJSON(
        USERS_FILE,
        users
      );

      res.status(201).json({
        ok: true,
        message:
          "User created successfully.",
        user:
          safeUser(newUser)
      });
    } catch (error) {
      console.error(
        "Create user error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to create user."
      });
    }
  }
);


// ============================================================
// UPDATE USER
// ============================================================

app.put(
  "/api/users/:id",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin"
  ),
  async (req, res) => {
    try {
      const user =
        users.find(
          u =>
            String(u.id) ===
            String(
              req.params.id
            )
        );

      if (!user) {
        return res.status(404).json({
          ok: false,
          error:
            "User not found."
        });
      }

      if (
        req.user.role ===
          "school_admin" &&
        String(user.schoolId) !==
          String(req.user.schoolId)
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "You cannot manage users from another school."
        });
      }

      if (
        req.body.fullName !==
        undefined
      ) {
        user.fullName =
          cleanString(
            req.body.fullName
          );
      }

      if (
        req.body.username !==
        undefined
      ) {
        const username =
          normalizeUsername(
            req.body.username
          );

        const duplicate =
          users.find(
            u =>
              String(u.id) !==
                String(user.id) &&
              normalizeUsername(
                u.username
              ) === username
          );

        if (duplicate) {
          return res.status(409).json({
            ok: false,
            error:
              "Username is already in use."
          });
        }

        user.username =
          username;
      }

      if (
        req.body.email !==
        undefined
      ) {
        const email =
          normalizeEmail(
            req.body.email
          );

        const duplicate =
          users.find(
            u =>
              String(u.id) !==
                String(user.id) &&
              normalizeEmail(
                u.email
              ) === email
          );

        if (duplicate) {
          return res.status(409).json({
            ok: false,
            error:
              "Email is already in use."
          });
        }

        user.email =
          email;
      }

      if (
        req.body.role !==
        undefined
      ) {
        if (
          req.user.role ===
          "school_admin"
        ) {
          if (
            ![
              "teacher",
              "student"
            ].includes(
              req.body.role
            )
          ) {
            return res.status(403).json({
              ok: false,
              error:
                "School admins cannot assign this role."
            });
          }
        }

        if (
          !isValidRole(
            req.body.role
          )
        ) {
          return res.status(400).json({
            ok: false,
            error:
              "Invalid role."
          });
        }

        user.role =
          req.body.role;
      }

      if (
        req.body.schoolId !==
          undefined &&
        req.user.role ===
          "superadmin"
      ) {
        user.schoolId =
          req.body.schoolId ||
          null;
      }

      if (
        req.body.password
      ) {
        user.passwordHash =
          await bcrypt.hash(
            String(
              req.body.password
            ),
            12
          );
      }

      if (
        req.body.active !==
        undefined
      ) {
        user.active =
          Boolean(
            req.body.active
          );
      }

      user.updatedAt = now();

      saveJSON(
        USERS_FILE,
        users
      );

      res.json({
        ok: true,
        user:
          safeUser(user)
      });
    } catch (error) {
      console.error(
        "Update user error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to update user."
      });
    }
  }
);


// ============================================================
// DELETE USER
// ============================================================

app.delete(
  "/api/users/:id",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin"
  ),
  (req, res) => {
    try {
      const index =
        users.findIndex(
          u =>
            String(u.id) ===
            String(
              req.params.id
            )
        );

      if (index === -1) {
        return res.status(404).json({
          ok: false,
          error:
            "User not found."
        });
      }

      const user =
        users[index];

      if (
        req.user.role ===
          "school_admin" &&
        String(user.schoolId) !==
          String(req.user.schoolId)
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "You cannot delete users from another school."
        });
      }

      if (
        String(user.id) ===
        String(req.user.id)
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "You cannot delete your own account."
        });
      }

      users.splice(index, 1);

      saveJSON(
        USERS_FILE,
        users
      );

      res.json({
        ok: true,
        message:
          "User deleted successfully."
      });
    } catch (error) {
      console.error(
        "Delete user error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to delete user."
      });
    }
  }
);


// ============================================================
// SUBJECTS
// ============================================================

app.get(
  "/api/subjects",
  requireAuth,
  (req, res) => {
    let list =
      subjects.slice();

    if (
      req.user.role !==
      "superadmin"
    ) {
      list =
        list.filter(
          s =>
            String(s.schoolId) ===
            String(
              req.user.schoolId
            )
        );
    }

    res.json({
      ok: true,
      count: list.length,
      subjects: list
    });
  }
);


app.post(
  "/api/subjects",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    try {
      const {
        name,
        code,
        description,
        schoolId
      } = req.body;

      if (!name) {
        return res.status(400).json({
          ok: false,
          error:
            "Subject name is required."
        });
      }

      let targetSchoolId =
        req.user.schoolId;

      if (
        req.user.role ===
          "superadmin" &&
        schoolId
      ) {
        targetSchoolId =
          schoolId;
      }

      if (!targetSchoolId) {
        return res.status(400).json({
          ok: false,
          error:
            "School is required."
        });
      }

      const subject = {
        id: id("subject"),

        schoolId:
          targetSchoolId,

        name:
          cleanString(name),

        code:
          cleanString(code),

        description:
          cleanString(
            description
          ),

        teacherIds: [],

        active: true,

        createdAt: now(),

        updatedAt: now()
      };

      subjects.push(subject);

      saveJSON(
        SUBJECTS_FILE,
        subjects
      );

      res.status(201).json({
        ok: true,
        subject
      });
    } catch (error) {
      console.error(
        "Create subject error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to create subject."
      });
    }
  }
);


app.put(
  "/api/subjects/:id",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    try {
      const subject =
        subjects.find(
          s =>
            String(s.id) ===
            String(
              req.params.id
            )
        );

      if (!subject) {
        return res.status(404).json({
          ok: false,
          error:
            "Subject not found."
        });
      }

      if (
        req.user.role !==
          "superadmin" &&
        String(subject.schoolId) !==
          String(
            req.user.schoolId
          )
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "Access denied."
        });
      }

      if (
        req.body.name !==
        undefined
      ) {
        subject.name =
          cleanString(
            req.body.name
          );
      }

      if (
        req.body.code !==
        undefined
      ) {
        subject.code =
          cleanString(
            req.body.code
          );
      }

      if (
        req.body.description !==
        undefined
      ) {
        subject.description =
          cleanString(
            req.body.description
          );
      }

      if (
        req.body.teacherIds &&
        Array.isArray(
          req.body.teacherIds
        )
      ) {
        subject.teacherIds =
          req.body.teacherIds;
      }

      if (
        req.body.active !==
        undefined
      ) {
        subject.active =
          Boolean(
            req.body.active
          );
      }

      subject.updatedAt = now();

      saveJSON(
        SUBJECTS_FILE,
        subjects
      );

      res.json({
        ok: true,
        subject
      });
    } catch (error) {
      console.error(
        "Update subject error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to update subject."
      });
    }
  }
);


app.delete(
  "/api/subjects/:id",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin"
  ),
  (req, res) => {
    try {
      const index =
        subjects.findIndex(
          s =>
            String(s.id) ===
            String(
              req.params.id
            )
        );

      if (index === -1) {
        return res.status(404).json({
          ok: false,
          error:
            "Subject not found."
        });
      }

      const subject =
        subjects[index];

      if (
        req.user.role !==
          "superadmin" &&
        String(subject.schoolId) !==
          String(
            req.user.schoolId
          )
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "Access denied."
        });
      }

      subjects.splice(index, 1);

      saveJSON(
        SUBJECTS_FILE,
        subjects
      );

      res.json({
        ok: true,
        message:
          "Subject deleted successfully."
      });
    } catch (error) {
      console.error(
        "Delete subject error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to delete subject."
      });
    }
  }
);


// ============================================================
// EXAMS / CBT
// ============================================================

app.get(
  "/api/exams",
  requireAuth,
  (req, res) => {
    let list =
      exams.slice();

    if (
      req.user.role !==
      "superadmin"
    ) {
      list =
        list.filter(
          e =>
            String(e.schoolId) ===
            String(
              req.user.schoolId
            )
        );
    }

    const output =
      list.map(exam => ({
        ...exam,

        questionCount:
          Array.isArray(
            exam.questionIds
          )
            ? exam.questionIds.length
            : questions.filter(
                q =>
                  String(
                    q.examId
                  ) ===
                  String(exam.id)
              ).length,

        subject:
          subjects.find(
            s =>
              String(s.id) ===
              String(
                exam.subjectId
              )
          ) || null
      }));

    res.json({
      ok: true,
      count: output.length,
      exams: output
    });
  }
);


app.post(
  "/api/exams",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    try {
      const {
        title,
        subjectId,
        description,
        durationMinutes,
        instructions,
        startAt,
        endAt,
        status,
        schoolId
      } = req.body;

      if (!title) {
        return res.status(400).json({
          ok: false,
          error:
            "Exam title is required."
        });
      }

      let targetSchoolId =
        req.user.schoolId;

      if (
        req.user.role ===
          "superadmin" &&
        schoolId
      ) {
        targetSchoolId =
          schoolId;
      }

      if (!targetSchoolId) {
        return res.status(400).json({
          ok: false,
          error:
            "School is required."
        });
      }

      const exam = {
        id: id("exam"),

        schoolId:
          targetSchoolId,

        title:
          cleanString(title),

        subjectId:
          subjectId || null,

        description:
          cleanString(
            description
          ),

        durationMinutes:
          Number(
            durationMinutes || 30
          ),

        instructions:
          cleanString(
            instructions
          ),

        startAt:
          startAt || null,

        endAt:
          endAt || null,

        status:
          status || "draft",

        questionIds: [],

        createdBy:
          req.user.id,

        active: true,

        createdAt: now(),

        updatedAt: now()
      };

      exams.push(exam);

      saveJSON(
        EXAMS_FILE,
        exams
      );

      res.status(201).json({
        ok: true,
        exam
      });
    } catch (error) {
      console.error(
        "Create exam error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to create exam."
      });
    }
  }
);


app.put(
  "/api/exams/:id",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    try {
      const exam =
        exams.find(
          e =>
            String(e.id) ===
            String(
              req.params.id
            )
        );

      if (!exam) {
        return res.status(404).json({
          ok: false,
          error:
            "Exam not found."
        });
      }

      if (
        req.user.role !==
          "superadmin" &&
        String(exam.schoolId) !==
          String(
            req.user.schoolId
          )
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "Access denied."
        });
      }

      const fields = [
        "title",
        "subjectId",
        "description",
        "durationMinutes",
        "instructions",
        "startAt",
        "endAt",
        "status",
        "active"
      ];

      fields.forEach(field => {
        if (
          req.body[field] !==
          undefined
        ) {
          exam[field] =
            req.body[field];
        }
      });

      if (
        req.body.durationMinutes !==
        undefined
      ) {
        exam.durationMinutes =
          Number(
            req.body.durationMinutes
          ) || 30;
      }

      exam.updatedAt = now();

      saveJSON(
        EXAMS_FILE,
        exams
      );

      res.json({
        ok: true,
        exam
      });
    } catch (error) {
      console.error(
        "Update exam error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to update exam."
      });
    }
  }
);


app.delete(
  "/api/exams/:id",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    try {
      const index =
        exams.findIndex(
          e =>
            String(e.id) ===
            String(
              req.params.id
            )
        );

      if (index === -1) {
        return res.status(404).json({
          ok: false,
          error:
            "Exam not found."
        });
      }

      const exam =
        exams[index];

      if (
        req.user.role !==
          "superadmin" &&
        String(exam.schoolId) !==
          String(
            req.user.schoolId
          )
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "Access denied."
        });
      }

      exams.splice(index, 1);

      questions =
        questions.filter(
          q =>
            String(q.examId) !==
            String(exam.id)
        );

      saveJSON(
        EXAMS_FILE,
        exams
      );

      saveJSON(
        QUESTIONS_FILE,
        questions
      );

      res.json({
        ok: true,
        message:
          "Exam deleted successfully."
      });
    } catch (error) {
      console.error(
        "Delete exam error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to delete exam."
      });
    }
  }
);


// ============================================================
// QUESTION BANK
// ============================================================

// GET QUESTION BANK
app.get(
  "/api/question-bank",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    try {
      const {
        search = "",
        subjectId = "",
        difficulty = "",
        examId = "",
        tags = ""
      } = req.query;

      let list =
        questions.slice();

      // MULTI-SCHOOL ISOLATION
      if (
        req.user.role !==
        "superadmin"
      ) {
        list =
          list.filter(
            q =>
              String(
                q.schoolId
              ) ===
              String(
                req.user.schoolId
              )
          );
      }

      // SEARCH
      const searchText =
        String(search)
          .trim()
          .toLowerCase();

      if (searchText) {
        list =
          list.filter(q => {
            return (
              String(
                q.question || ""
              )
                .toLowerCase()
                .includes(
                  searchText
                ) ||

              String(
                q.tags || ""
              )
                .toLowerCase()
                .includes(
                  searchText
                )
            );
          });
      }

      // SUBJECT FILTER
      if (subjectId) {
        list =
          list.filter(
            q =>
              String(
                q.subjectId
              ) ===
              String(subjectId)
          );
      }

      // EXAM FILTER
      if (examId) {
        list =
          list.filter(
            q =>
              String(
                q.examId
              ) ===
              String(examId)
          );
      }

      // DIFFICULTY FILTER
      if (difficulty) {
        list =
          list.filter(
            q =>
              String(
                q.difficulty ||
                  ""
              ).toLowerCase() ===
              String(
                difficulty
              ).toLowerCase()
          );
      }

      // TAG FILTER
      if (tags) {
        const wanted =
          String(tags)
            .split(",")
            .map(
              x =>
                x
                  .trim()
                  .toLowerCase()
            )
            .filter(Boolean);

        list =
          list.filter(q => {
            const questionTags =
              String(
                q.tags || ""
              )
                .split(",")
                .map(
                  x =>
                    x
                      .trim()
                      .toLowerCase()
                );

            return wanted.some(
              tag =>
                questionTags.includes(
                  tag
                )
            );
          });
      }

      const output =
        list.map(q => {
          const subject =
            subjects.find(
              s =>
                String(s.id) ===
                String(
                  q.subjectId
                )
            );

          const exam =
            exams.find(
              e =>
                String(e.id) ===
                String(q.examId)
            );

          return {
            ...safeQuestion(
              q,
              true
            ),

            subjectName:
              subject?.name ||
              "",

            subjectCode:
              subject?.code ||
              "",

            examTitle:
              exam?.title ||
              ""
          };
        });

      res.json({
        ok: true,
        count: output.length,
        questions: output
      });
    } catch (error) {
      console.error(
        "Question bank error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to load question bank."
      });
    }
  }
);


// GET QUESTIONS
app.get(
  "/api/questions",
  requireAuth,
  (req, res) => {
    let list =
      questions.slice();

    if (
      req.user.role !==
      "superadmin"
    ) {
      list =
        list.filter(
          q =>
            String(q.schoolId) ===
            String(
              req.user.schoolId
            )
        );
    }

    if (req.query.examId) {
      list =
        list.filter(
          q =>
            String(q.examId) ===
            String(
              req.query.examId
            )
        );
    }

    if (req.query.subjectId) {
      list =
        list.filter(
          q =>
            String(
              q.subjectId
            ) ===
            String(
              req.query.subjectId
            )
        );
    }

    const canSeeAnswer =
      [
        "superadmin",
        "school_admin",
        "teacher"
      ].includes(
        req.user.role
      );

    res.json({
      ok: true,
      count: list.length,

      questions:
        list.map(q =>
          safeQuestion(
            q,
            canSeeAnswer
          )
        )
    });
  }
);


// ADD SINGLE QUESTION
app.post(
  "/api/questions",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    try {
      const {
        question,
        options,
        answer,
        subjectId,
        examId,
        points,
        difficulty,
        tags,
        schoolId
      } = req.body;

      if (
        !question ||
        !Array.isArray(options)
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Question and options are required."
        });
      }

      if (options.length < 2) {
        return res.status(400).json({
          ok: false,
          error:
            "At least two options are required."
        });
      }

      let targetSchoolId =
        req.user.schoolId;

      if (
        req.user.role ===
          "superadmin" &&
        schoolId
      ) {
        targetSchoolId =
          schoolId;
      }

      if (
        examId
      ) {
        const exam =
          exams.find(
            e =>
              String(e.id) ===
              String(examId)
          );

        if (!exam) {
          return res.status(404).json({
            ok: false,
            error:
              "Exam not found."
          });
        }

        if (
          req.user.role !==
            "superadmin" &&
          String(exam.schoolId) !==
            String(
              req.user.schoolId
            )
        ) {
          return res.status(403).json({
            ok: false,
            error:
              "Cannot add a question to another school."
          });
        }

        targetSchoolId =
          exam.schoolId;
      }

      let correctAnswer =
        Number(answer);

      if (
        !Number.isInteger(
          correctAnswer
        ) ||
        correctAnswer < 0 ||
        correctAnswer >=
          options.length
      ) {
        correctAnswer = 0;
      }

      const newQuestion = {
        id: id("question"),

        schoolId:
          targetSchoolId,

        subjectId:
          subjectId || null,

        examId:
          examId || null,

        question:
          String(question).trim(),

        options:
          options.map(
            option =>
              String(option)
          ),

        answer:
          correctAnswer,

        points:
          Number(points) > 0
            ? Number(points)
            : 1,

        difficulty:
          [
            "easy",
            "medium",
            "hard"
          ].includes(
            String(
              difficulty ||
                "medium"
            ).toLowerCase()
          )
            ? String(
                difficulty ||
                  "medium"
              ).toLowerCase()
            : "medium",

        tags:
          Array.isArray(tags)
            ? tags.join(", ")
            : String(tags || ""),

        active: true,

        createdBy:
          req.user.id,

        createdAt: now(),

        updatedAt: now()
      };

      questions.push(
        newQuestion
      );

      if (examId) {
        const exam =
          exams.find(
            e =>
              String(e.id) ===
              String(examId)
          );

        if (exam) {
          if (
            !Array.isArray(
              exam.questionIds
            )
          ) {
            exam.questionIds =
              [];
          }

          if (
            !exam.questionIds.includes(
              newQuestion.id
            )
          ) {
            exam.questionIds.push(
              newQuestion.id
            );
          }

          exam.updatedAt =
            now();

          saveJSON(
            EXAMS_FILE,
            exams
          );
        }
      }

      saveJSON(
        QUESTIONS_FILE,
        questions
      );

      res.status(201).json({
        ok: true,
        question:
          safeQuestion(
            newQuestion,
            true
          )
      });
    } catch (error) {
      console.error(
        "Create question error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to create question."
      });
    }
  }
);


// ============================================================
// BULK JSON QUESTION IMPORT
// ============================================================

app.post(
  "/api/question-bank/bulk",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    try {
      const {
        examId,
        subjectId,
        questions: incoming
      } = req.body;

      if (
        !Array.isArray(incoming)
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "questions must be an array."
        });
      }

      let exam = null;

      if (examId) {
        exam =
          exams.find(
            e =>
              String(e.id) ===
              String(examId)
          );

        if (!exam) {
          return res.status(404).json({
            ok: false,
            error:
              "Exam not found."
          });
        }

        if (
          req.user.role !==
            "superadmin" &&
          String(exam.schoolId) !==
            String(
              req.user.schoolId
            )
        ) {
          return res.status(403).json({
            ok: false,
            error:
              "You cannot import questions into another school."
          });
        }
      }

      let targetSchoolId =
        exam?.schoolId ||
        req.user.schoolId;

      if (
        !targetSchoolId &&
        req.user.role ===
          "superadmin"
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "schoolId or examId is required for superadmin imports."
        });
      }

      const created = [];
      const skipped = [];

      incoming.forEach(
        (item, index) => {
          if (
            !item ||
            !item.question
          ) {
            skipped.push({
              index,
              reason:
                "Missing question text."
            });

            return;
          }

          if (
            !Array.isArray(
              item.options
            ) ||
            item.options.length <
              2
          ) {
            skipped.push({
              index,
              reason:
                "At least two options are required."
            });

            return;
          }

          let answer =
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
            answer = 0;
          }

          const newQuestion = {
            id:
              id("question"),

            schoolId:
              targetSchoolId,

            subjectId:
              item.subjectId ||
              subjectId ||
              exam?.subjectId ||
              null,

            examId:
              item.examId ||
              exam?.id ||
              null,

            question:
              String(
                item.question
              ).trim(),

            options:
              item.options.map(
                option =>
                  String(option)
              ),

            answer,

            points:
              Number(
                item.points
              ) > 0
                ? Number(
                    item.points
                  )
                : 1,

            difficulty:
              [
                "easy",
                "medium",
                "hard"
              ].includes(
                String(
                  item.difficulty ||
                    "medium"
                ).toLowerCase()
              )
                ? String(
                    item.difficulty ||
                      "medium"
                  ).toLowerCase()
                : "medium",

            tags:
              Array.isArray(
                item.tags
              )
                ? item.tags.join(
                    ", "
                  )
                : String(
                    item.tags ||
                      ""
                  ),

            active: true,

            createdBy:
              req.user.id,

            createdAt: now(),

            updatedAt: now()
          };

          questions.push(
            newQuestion
          );

          created.push(
            newQuestion
          );

          const questionExam =
            exams.find(
              e =>
                String(e.id) ===
                String(
                  newQuestion.examId
                )
            );

          if (
            questionExam
          ) {
            if (
              !Array.isArray(
                questionExam.questionIds
              )
            ) {
              questionExam.questionIds =
                [];
            }

            if (
              !questionExam.questionIds.includes(
                newQuestion.id
              )
            ) {
              questionExam.questionIds.push(
                newQuestion.id
              );
            }

            questionExam.updatedAt =
              now();
          }
        }
      );

      saveJSON(
        QUESTIONS_FILE,
        questions
      );

      saveJSON(
        EXAMS_FILE,
        exams
      );

      res.status(201).json({
        ok: true,

        message:
          `${created.length} question(s) imported successfully.`,

        count:
          created.length,

        skipped:
          skipped.length,

        questions:
          created.map(q =>
            safeQuestion(
              q,
              true
            )
          ),

        skippedItems:
          skipped
      });
    } catch (error) {
      console.error(
        "Bulk question import error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to import questions."
      });
    }
  }
);


// ============================================================
// ADD QUESTION DIRECTLY TO EXAM
// ============================================================

app.post(
  "/api/exams/:id/questions",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    try {
      const exam =
        exams.find(
          e =>
            String(e.id) ===
            String(
              req.params.id
            )
        );

      if (!exam) {
        return res.status(404).json({
          ok: false,
          error:
            "Exam not found."
        });
      }

      if (
        req.user.role !==
          "superadmin" &&
        String(exam.schoolId) !==
          String(
            req.user.schoolId
          )
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "Access denied."
        });
      }

      const {
        question,
        options,
        answer,
        subjectId,
        points,
        difficulty,
        tags
      } = req.body;

      if (
        !question ||
        !Array.isArray(options)
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Question and options are required."
        });
      }

      let correctAnswer =
        Number(answer);

      if (
        !Number.isInteger(
          correctAnswer
        ) ||
        correctAnswer < 0 ||
        correctAnswer >=
          options.length
      ) {
        correctAnswer = 0;
      }

      const newQuestion = {
        id: id("question"),

        schoolId:
          exam.schoolId,

        subjectId:
          subjectId ||
          exam.subjectId ||
          null,

        examId:
          exam.id,

        question:
          String(question).trim(),

        options:
          options.map(
            option =>
              String(option)
          ),

        answer:
          correctAnswer,

        points:
          Number(points) > 0
            ? Number(points)
            : 1,

        difficulty:
          [
            "easy",
            "medium",
            "hard"
          ].includes(
            String(
              difficulty ||
                "medium"
            ).toLowerCase()
          )
            ? String(
                difficulty ||
                  "medium"
              ).toLowerCase()
            : "medium",

        tags:
          Array.isArray(tags)
            ? tags.join(", ")
            : String(tags || ""),

        active: true,

        createdBy:
          req.user.id,

        createdAt: now(),

        updatedAt: now()
      };

      questions.push(
        newQuestion
      );

      if (
        !Array.isArray(
          exam.questionIds
        )
      ) {
        exam.questionIds =
          [];
      }

      exam.questionIds.push(
        newQuestion.id
      );

      exam.updatedAt =
        now();

      saveJSON(
        QUESTIONS_FILE,
        questions
      );

      saveJSON(
        EXAMS_FILE,
        exams
      );

      res.status(201).json({
        ok: true,
        question:
          safeQuestion(
            newQuestion,
            true
          )
      });
    } catch (error) {
      console.error(
        "Exam question error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to add question."
      });
    }
  }
);


// ============================================================
// UPDATE QUESTION
// ============================================================

app.put(
  "/api/questions/:id",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    try {
      const question =
        questions.find(
          q =>
            String(q.id) ===
            String(
              req.params.id
            )
        );

      if (!question) {
        return res.status(404).json({
          ok: false,
          error:
            "Question not found."
        });
      }

      if (
        req.user.role !==
          "superadmin" &&
        String(
          question.schoolId
        ) !==
          String(
            req.user.schoolId
          )
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "Access denied."
        });
      }

      if (
        req.body.question !==
        undefined
      ) {
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
        if (
          req.body.options.length <
          2
        ) {
          return res.status(400).json({
            ok: false,
            error:
              "At least two options are required."
          });
        }

        question.options =
          req.body.options.map(
            option =>
              String(option)
          );
      }

      if (
        req.body.answer !==
        undefined
      ) {
        const answer =
          Number(
            req.body.answer
          );

        if (
          Number.isInteger(
            answer
          ) &&
          answer >= 0 &&
          answer <
            question.options.length
        ) {
          question.answer =
            answer;
        }
      }

      if (
        req.body.subjectId !==
        undefined
      ) {
        question.subjectId =
          req.body.subjectId;
      }

      if (
        req.body.examId !==
        undefined
      ) {
        const newExam =
          exams.find(
            e =>
              String(e.id) ===
              String(
                req.body.examId
              )
          );

        if (!newExam) {
          return res.status(404).json({
            ok: false,
            error:
              "Exam not found."
          });
        }

        if (
          req.user.role !==
            "superadmin" &&
          String(
            newExam.schoolId
          ) !==
            String(
              req.user.schoolId
            )
        ) {
          return res.status(403).json({
            ok: false,
            error:
              "Cannot move question to another school."
          });
        }

        const oldExam =
          exams.find(
            e =>
              String(e.id) ===
              String(
                question.examId
              )
          );

        if (
          oldExam &&
          Array.isArray(
            oldExam.questionIds
          )
        ) {
          oldExam.questionIds =
            oldExam.questionIds.filter(
              idValue =>
                String(
                  idValue
                ) !==
                String(
                  question.id
                )
            );
        }

        if (
          !Array.isArray(
            newExam.questionIds
          )
        ) {
          newExam.questionIds =
            [];
        }

        if (
          !newExam.questionIds.includes(
            question.id
          )
        ) {
          newExam.questionIds.push(
            question.id
          );
        }

        question.examId =
          newExam.id;

        saveJSON(
          EXAMS_FILE,
          exams
        );
      }

      if (
        req.body.points !==
        undefined
      ) {
        question.points =
          Number(
            req.body.points
          ) > 0
            ? Number(
                req.body.points
              )
            : 1;
      }

      if (
        req.body.difficulty !==
        undefined
      ) {
        const difficulty =
          String(
            req.body.difficulty
          ).toLowerCase();

        if (
          [
            "easy",
            "medium",
            "hard"
          ].includes(
            difficulty
          )
        ) {
          question.difficulty =
            difficulty;
        }
      }

      if (
        req.body.tags !==
        undefined
      ) {
        question.tags =
          Array.isArray(
            req.body.tags
          )
            ? req.body.tags.join(
                ", "
              )
            : String(
                req.body.tags
              );
      }

      if (
        req.body.active !==
        undefined
      ) {
        question.active =
          Boolean(
            req.body.active
          );
      }

      question.updatedAt =
        now();

      saveJSON(
        QUESTIONS_FILE,
        questions
      );

      res.json({
        ok: true,
        question:
          safeQuestion(
            question,
            true
          )
      });
    } catch (error) {
      console.error(
        "Update question error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to update question."
      });
    }
  }
);


// ============================================================
// DELETE QUESTION
// ============================================================

app.delete(
  "/api/questions/:id",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    try {
      const index =
        questions.findIndex(
          q =>
            String(q.id) ===
            String(
              req.params.id
            )
        );

      if (index === -1) {
        return res.status(404).json({
          ok: false,
          error:
            "Question not found."
        });
      }

      const question =
        questions[index];

      if (
        req.user.role !==
          "superadmin" &&
        String(
          question.schoolId
        ) !==
          String(
            req.user.schoolId
          )
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "Access denied."
        });
      }

      questions.splice(
        index,
        1
      );

      exams.forEach(
        exam => {
          if (
            Array.isArray(
              exam.questionIds
            )
          ) {
            exam.questionIds =
              exam.questionIds.filter(
                questionId =>
                  String(
                    questionId
                  ) !==
                  String(
                    question.id
                  )
              );
          }

          exam.updatedAt =
            now();
        }
      );

      saveJSON(
        QUESTIONS_FILE,
        questions
      );

      saveJSON(
        EXAMS_FILE,
        exams
      );

      res.json({
        ok: true,
        message:
          "Question deleted successfully."
      });
    } catch (error) {
      console.error(
        "Delete question error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to delete question."
      });
    }
  }
);


// ============================================================
// START CBT
// ============================================================

app.post(
  "/api/exams/:id/start",
  requireAuth,
  requireRole("student"),
  (req, res) => {
    try {
      const exam =
        exams.find(
          e =>
            String(e.id) ===
            String(
              req.params.id
            )
        );

      if (!exam) {
        return res.status(404).json({
          ok: false,
          error:
            "Exam not found."
        });
      }

      if (
        String(exam.schoolId) !==
        String(
          req.user.schoolId
        )
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "This exam does not belong to your school."
        });
      }

      if (
        exam.active === false
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "This exam is inactive."
        });
      }

      const current =
        Date.now();

      if (exam.startAt) {
        const start =
          new Date(
            exam.startAt
          ).getTime();

        if (
          Number.isFinite(start) &&
          current < start
        ) {
          return res.status(403).json({
            ok: false,
            error:
              "This exam has not started yet."
          });
        }
      }

      if (exam.endAt) {
        const end =
          new Date(
            exam.endAt
          ).getTime();

        if (
          Number.isFinite(end) &&
          current > end
        ) {
          return res.status(403).json({
            ok: false,
            error:
              "This exam has ended."
          });
        }
      }

      const examQuestions =
        questions.filter(
          q =>
            String(
              q.examId
            ) ===
              String(exam.id) &&
            q.active !== false &&
            String(
              q.schoolId
            ) ===
              String(
                req.user.schoolId
              )
        );

      res.json({
        ok: true,

        exam: {
          ...exam,

          questions:
            examQuestions.map(
              q =>
                safeQuestion(
                  q,
                  false
                )
            )
        }
      });
    } catch (error) {
      console.error(
        "Start exam error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to start exam."
      });
    }
  }
);


// ============================================================
// SUBMIT CBT
// ============================================================

app.post(
  "/api/exams/:id/submit",
  requireAuth,
  requireRole("student"),
  (req, res) => {
    try {
      const exam =
        exams.find(
          e =>
            String(e.id) ===
            String(
              req.params.id
            )
        );

      if (!exam) {
        return res.status(404).json({
          ok: false,
          error:
            "Exam not found."
        });
      }

      if (
        String(exam.schoolId) !==
        String(
          req.user.schoolId
        )
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "Access denied."
        });
      }

      const submittedAnswers =
        req.body.answers || {};

      const examQuestions =
        questions.filter(
          q =>
            String(q.examId) ===
              String(exam.id) &&
            q.active !== false &&
            String(
              q.schoolId
            ) ===
              String(
                req.user.schoolId
              )
        );

      let score = 0;
      let totalPoints = 0;

      const answerDetails = [];

      examQuestions.forEach(
        q => {
          const points =
            Number(
              q.points || 1
            );

          totalPoints +=
            points;

          let submitted =
            submittedAnswers[
              q.id
            ];

          if (
            submitted ===
            undefined &&
            submittedAnswers[
              String(q.id)
            ] !== undefined
          ) {
            submitted =
              submittedAnswers[
                String(q.id)
              ];
          }

          const selected =
            Number(submitted);

          const correct =
            selected ===
            Number(q.answer);

          if (correct) {
            score += points;
          }

          answerDetails.push({
            questionId:
              q.id,

            selected:
              Number.isInteger(
                selected
              )
                ? selected
                : null,

            correct:
              Number(q.answer),

            isCorrect:
              correct,

            points:
              correct
                ? points
                : 0
          });
        }
      );

      const percentage =
        totalPoints > 0
          ? Number(
              (
                (score /
                  totalPoints) *
                100
              ).toFixed(2)
            )
          : 0;

      const result = {
        id: id("result"),

        schoolId:
          req.user.schoolId,

        examId:
          exam.id,

        studentId:
          req.user.id,

        score,

        totalPoints,

        percentage,

        answers:
          answerDetails,

        submittedAt:
          now(),

        createdAt:
          now()
      };

      results.push(result);

      saveJSON(
        RESULTS_FILE,
        results
      );

      res.json({
        ok: true,

        message:
          "Exam submitted successfully.",

        result
      });
    } catch (error) {
      console.error(
        "Submit exam error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to submit exam."
      });
    }
  }
);


// ============================================================
// RESULTS
// ============================================================

app.get(
  "/api/results",
  requireAuth,
  (req, res) => {
    let list =
      results.slice();

    if (
      req.user.role ===
      "student"
    ) {
      list =
        list.filter(
          r =>
            String(
              r.studentId
            ) ===
            String(
              req.user.id
            )
        );
    } else if (
      req.user.role !==
      "superadmin"
    ) {
      list =
        list.filter(
          r =>
            String(
              r.schoolId
            ) ===
            String(
              req.user.schoolId
            )
        );
    }

    const output =
      list.map(result => {
        const exam =
          exams.find(
            e =>
              String(e.id) ===
              String(
                result.examId
              )
          );

        const student =
          users.find(
            u =>
              String(u.id) ===
              String(
                result.studentId
              )
          );

        return {
          ...result,

          examTitle:
            exam?.title ||
            "",

          studentName:
            student?.fullName ||
            "",

          studentEmail:
            student?.email ||
            ""
        };
      });

    res.json({
      ok: true,
      count: output.length,
      results: output
    });
  }
);


// ============================================================
// ANNOUNCEMENTS
// ============================================================

app.get(
  "/api/announcements",
  requireAuth,
  (req, res) => {
    let list =
      announcements.slice();

    if (
      req.user.role !==
      "superadmin"
    ) {
      list =
        list.filter(
          a =>
            String(
              a.schoolId
            ) ===
            String(
              req.user.schoolId
            )
        );
    }

    res.json({
      ok: true,
      count: list.length,
      announcements:
        list.sort(
          (a, b) =>
            new Date(
              b.createdAt
            ) -
            new Date(
              a.createdAt
            )
        )
    });
  }
);


app.post(
  "/api/announcements",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    try {
      const {
        title,
        message,
        audience,
        schoolId
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

      let targetSchoolId =
        req.user.schoolId;

      if (
        req.user.role ===
          "superadmin" &&
        schoolId
      ) {
        targetSchoolId =
          schoolId;
      }

      if (!targetSchoolId) {
        return res.status(400).json({
          ok: false,
          error:
            "School is required."
        });
      }

      const announcement = {
        id:
          id("announcement"),

        schoolId:
          targetSchoolId,

        title:
          cleanString(title),

        message:
          cleanString(message),

        audience:
          audience ||
          "all",

        createdBy:
          req.user.id,

        createdAt:
          now(),

        updatedAt:
          now()
      };

      announcements.push(
        announcement
      );

      saveJSON(
        ANNOUNCEMENTS_FILE,
        announcements
      );

      res.status(201).json({
        ok: true,
        announcement
      });
    } catch (error) {
      console.error(
        "Announcement error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to create announcement."
      });
    }
  }
);


app.put(
  "/api/announcements/:id",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    try {
      const announcement =
        announcements.find(
          a =>
            String(a.id) ===
            String(
              req.params.id
            )
        );

      if (!announcement) {
        return res.status(404).json({
          ok: false,
          error:
            "Announcement not found."
        });
      }

      if (
        req.user.role !==
          "superadmin" &&
        String(
          announcement.schoolId
        ) !==
          String(
            req.user.schoolId
          )
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "Access denied."
        });
      }

      if (
        req.body.title !==
        undefined
      ) {
        announcement.title =
          cleanString(
            req.body.title
          );
      }

      if (
        req.body.message !==
        undefined
      ) {
        announcement.message =
          cleanString(
            req.body.message
          );
      }

      if (
        req.body.audience !==
        undefined
      ) {
        announcement.audience =
          req.body.audience;
      }

      announcement.updatedAt =
        now();

      saveJSON(
        ANNOUNCEMENTS_FILE,
        announcements
      );

      res.json({
        ok: true,
        announcement
      });
    } catch (error) {
      console.error(
        "Update announcement error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to update announcement."
      });
    }
  }
);


app.delete(
  "/api/announcements/:id",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    try {
      const index =
        announcements.findIndex(
          a =>
            String(a.id) ===
            String(
              req.params.id
            )
        );

      if (index === -1) {
        return res.status(404).json({
          ok: false,
          error:
            "Announcement not found."
        });
      }

      const announcement =
        announcements[index];

      if (
        req.user.role !==
          "superadmin" &&
        String(
          announcement.schoolId
        ) !==
          String(
            req.user.schoolId
          )
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "Access denied."
        });
      }

      announcements.splice(
        index,
        1
      );

      saveJSON(
        ANNOUNCEMENTS_FILE,
        announcements
      );

      res.json({
        ok: true,
        message:
          "Announcement deleted."
      });
    } catch (error) {
      console.error(
        "Delete announcement error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to delete announcement."
      });
    }
  }
);


// ============================================================
// SCHOOL ADMIN SUMMARY
// ============================================================

app.get(
  "/api/admin/summary",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin"
  ),
  (req, res) => {
    if (
      req.user.role ===
      "superadmin"
    ) {
      return res.json({
        ok: true,

        summary: {
          schools:
            schools.length,

          users:
            users.length,

          teachers:
            users.filter(
              u =>
                u.role ===
                "teacher"
            ).length,

          students:
            users.filter(
              u =>
                u.role ===
                "student"
            ).length,

          schoolAdmins:
            users.filter(
              u =>
                u.role ===
                "school_admin"
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
      req.user.schoolId;

    res.json({
      ok: true,

      summary: {
        schools: 1,

        users:
          users.filter(
            u =>
              String(
                u.schoolId
              ) ===
              String(
                schoolId
              )
          ).length,

        teachers:
          users.filter(
            u =>
              String(
                u.schoolId
              ) ===
                String(
                  schoolId
                ) &&
              u.role ===
                "teacher"
          ).length,

        students:
          users.filter(
            u =>
              String(
                u.schoolId
              ) ===
                String(
                  schoolId
                ) &&
              u.role ===
                "student"
          ).length,

        schoolAdmins:
          users.filter(
            u =>
              String(
                u.schoolId
              ) ===
                String(
                  schoolId
                ) &&
              u.role ===
                "school_admin"
          ).length,

        subjects:
          subjects.filter(
            s =>
              String(
                s.schoolId
              ) ===
              String(
                schoolId
              )
          ).length,

        exams:
          exams.filter(
            e =>
              String(
                e.schoolId
              ) ===
              String(
                schoolId
              )
          ).length,

        questions:
          questions.filter(
            q =>
              String(
                q.schoolId
              ) ===
              String(
                schoolId
              )
          ).length,

        results:
          results.filter(
            r =>
              String(
                r.schoolId
              ) ===
              String(
                schoolId
              )
          ).length,

        announcements:
          announcements.filter(
            a =>
              String(
                a.schoolId
              ) ===
              String(
                schoolId
              )
          ).length
      }
    });
  }
);


// ============================================================
// TEACHER SUMMARY
// ============================================================

app.get(
  "/api/teacher/summary",
  requireAuth,
  requireRole(
    "teacher",
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    const schoolId =
      req.user.role ===
      "superadmin"
        ? null
        : req.user.schoolId;

    const schoolFilter =
      item =>
        !schoolId ||
        String(
          item.schoolId
        ) ===
          String(schoolId);

    res.json({
      ok: true,

      summary: {
        subjects:
          subjects.filter(
            schoolFilter
          ).length,

        exams:
          exams.filter(
            schoolFilter
          ).length,

        questions:
          questions.filter(
            schoolFilter
          ).length,

        results:
          results.filter(
            schoolFilter
          ).length,

        announcements:
          announcements.filter(
            schoolFilter
          ).length
      }
    });
  }
);


// ============================================================
// STUDENT SUMMARY
// ============================================================

app.get(
  "/api/student/summary",
  requireAuth,
  requireRole("student"),
  (req, res) => {
    const schoolId =
      req.user.schoolId;

    const studentResults =
      results.filter(
        result =>
          String(
            result.studentId
          ) ===
          String(
            req.user.id
          )
      );

    const schoolExams =
      exams.filter(
        exam =>
          String(
            exam.schoolId
          ) ===
          String(
            schoolId
          )
      );

    res.json({
      ok: true,

      summary: {
        exams:
          schoolExams.length,

        completedExams:
          studentResults.length,

        results:
          studentResults.length,

        averageScore:
          studentResults.length
            ? Number(
                (
                  studentResults.reduce(
                    (
                      total,
                      result
                    ) =>
                      total +
                      Number(
                        result.percentage ||
                          0
                      ),
                    0
                  ) /
                  studentResults.length
                ).toFixed(2)
              )
            : 0,

        announcements:
          announcements.filter(
            a =>
              String(
                a.schoolId
              ) ===
              String(
                schoolId
              )
          ).length
      }
    });
  }
);


// ============================================================
// SUPERADMIN - SCHOOLS
// ============================================================

app.get(
  "/api/admin/schools",
  requireAuth,
  requireRole("superadmin"),
  (req, res) => {
    const output =
      schools.map(
        school => {
          const schoolUsers =
            users.filter(
              user =>
                String(
                  user.schoolId
                ) ===
                String(
                  school.id
                )
            );

          return {
            ...safeSchool(
              school
            ),

            userCount:
              schoolUsers.length,

            teacherCount:
              schoolUsers.filter(
                u =>
                  u.role ===
                  "teacher"
              ).length,

            studentCount:
              schoolUsers.filter(
                u =>
                  u.role ===
                  "student"
              ).length,

            adminCount:
              schoolUsers.filter(
                u =>
                  u.role ===
                  "school_admin"
              ).length,

            subjectCount:
              subjects.filter(
                s =>
                  String(
                    s.schoolId
                  ) ===
                  String(
                    school.id
                  )
              ).length,

            examCount:
              exams.filter(
                e =>
                  String(
                    e.schoolId
                  ) ===
                  String(
                    school.id
                  )
              ).length,

            questionCount:
              questions.filter(
                q =>
                  String(
                    q.schoolId
                  ) ===
                  String(
                    school.id
                  )
              ).length
          };
        }
      );

    res.json({
      ok: true,
      count:
        output.length,
      schools:
        output
    });
  }
);


// ============================================================
// SUPERADMIN CREATE SCHOOL
// ============================================================

app.post(
  "/api/admin/schools",
  requireAuth,
  requireRole("superadmin"),
  (req, res) => {
    try {
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

      const school = {
        id:
          id("school"),

        name:
          cleanString(name),

        motto:
          cleanString(motto),

        logo: "",

        primaryColor:
          cleanString(
            primaryColor,
            "#2563eb"
          ),

        secondaryColor:
          cleanString(
            secondaryColor,
            "#16a34a"
          ),

        theme:
          ["light", "dark"].includes(
            String(
              theme ||
                "light"
            )
          )
            ? String(
                theme ||
                  "light"
              )
            : "light",

        active: true,

        createdAt:
          now(),

        updatedAt:
          now()
      };

      schools.push(
        school
      );

      saveJSON(
        SCHOOLS_FILE,
        schools
      );

      res.status(201).json({
        ok: true,
        school:
          safeSchool(school)
      });
    } catch (error) {
      console.error(
        "Superadmin school creation error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to create school."
      });
    }
  }
);


// ============================================================
// SUPERADMIN UPDATE SCHOOL
// ============================================================

app.put(
  "/api/admin/schools/:id",
  requireAuth,
  requireRole("superadmin"),
  (req, res) => {
    try {
      const school =
        schools.find(
          s =>
            String(s.id) ===
            String(
              req.params.id
            )
        );

      if (!school) {
        return res.status(404).json({
          ok: false,
          error:
            "School not found."
        });
      }

      if (
        req.body.name !==
        undefined
      ) {
        school.name =
          cleanString(
            req.body.name
          );
      }

      if (
        req.body.motto !==
        undefined
      ) {
        school.motto =
          cleanString(
            req.body.motto
          );
      }

      if (
        req.body.primaryColor !==
        undefined
      ) {
        school.primaryColor =
          cleanString(
            req.body.primaryColor
          );
      }

      if (
        req.body.secondaryColor !==
        undefined
      ) {
        school.secondaryColor =
          cleanString(
            req.body.secondaryColor
          );
      }

      if (
        req.body.theme !==
        undefined
      ) {
        if (
          [
            "light",
            "dark"
          ].includes(
            String(
              req.body.theme
            )
          )
        ) {
          school.theme =
            String(
              req.body.theme
            );
        }
      }

      if (
        req.body.active !==
        undefined
      ) {
        school.active =
          Boolean(
            req.body.active
          );
      }

      school.updatedAt =
        now();

      saveJSON(
        SCHOOLS_FILE,
        schools
      );

      res.json({
        ok: true,
        school:
          safeSchool(school)
      });
    } catch (error) {
      console.error(
        "Superadmin school update error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to update school."
      });
    }
  }
);


// ============================================================
// SUPERADMIN DEACTIVATE SCHOOL
// ============================================================

app.delete(
  "/api/admin/schools/:id",
  requireAuth,
  requireRole("superadmin"),
  (req, res) => {
    try {
      const school =
        schools.find(
          s =>
            String(s.id) ===
            String(
              req.params.id
            )
        );

      if (!school) {
        return res.status(404).json({
          ok: false,
          error:
            "School not found."
        });
      }

      school.active = false;
      school.updatedAt =
        now();

      saveJSON(
        SCHOOLS_FILE,
        schools
      );

      res.json({
        ok: true,
        message:
          "School deactivated.",
        school:
          safeSchool(school)
      });
    } catch (error) {
      console.error(
        "Deactivate school error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to deactivate school."
      });
    }
  }
);


// ============================================================
// SUPERADMIN ALL USERS
// ============================================================

app.get(
  "/api/admin/users",
  requireAuth,
  requireRole("superadmin"),
  (req, res) => {
    const output =
      users.map(user => {
        const school =
          schools.find(
            s =>
              String(s.id) ===
              String(
                user.schoolId
              )
          );

        return {
          ...safeUser(user),

          school:
            school
              ? safeSchool(
                  school
                )
              : null
        };
      });

    res.json({
      ok: true,
      count:
        output.length,
      users:
        output
    });
  }
);


// ============================================================
// SUPERADMIN SETTINGS
// ============================================================

app.get(
  "/api/admin/settings",
  requireAuth,
  requireRole("superadmin"),
  (req, res) => {
    res.json({
      ok: true,
      settings
    });
  }
);


app.put(
  "/api/admin/settings",
  requireAuth,
  requireRole("superadmin"),
  (req, res) => {
    try {
      if (
        req.body.platformName !==
        undefined
      ) {
        settings.platformName =
          cleanString(
            req.body.platformName
          );
      }

      if (
        req.body.platformDescription !==
        undefined
      ) {
        settings.platformDescription =
          cleanString(
            req.body.platformDescription
          );
      }

      if (
        req.body.defaultTheme !==
        undefined
      ) {
        settings.defaultTheme =
          [
            "light",
            "dark"
          ].includes(
            String(
              req.body.defaultTheme
            )
          )
            ? String(
                req.body.defaultTheme
              )
            : settings.defaultTheme;
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

      settings.updatedAt =
        now();

      saveJSON(
        SETTINGS_FILE,
        settings
      );

      res.json({
        ok: true,
        settings
      });
    } catch (error) {
      console.error(
        "Settings update error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Failed to update settings."
      });
    }
  }
);


// ============================================================
// ENSURE SUPERADMIN
// ============================================================

async function ensureSuperadmin() {
  const email =
    normalizeEmail(
      process.env.SUPERADMIN_EMAIL ||
        ""
    );

  const username =
    normalizeUsername(
      process.env.SUPERADMIN_USERNAME ||
        "superadmin"
    );

  const password =
    process.env.SUPERADMIN_PASSWORD ||
    "";

  const fullName =
    process.env.SUPERADMIN_NAME ||
    "SchoolHub Super Admin";

  if (!email || !password) {
    console.log(
      "Superadmin bootstrap: environment variables not configured."
    );

    return;
  }

  let user =
    users.find(
      u =>
        normalizeEmail(
          u.email
        ) === email ||
        normalizeUsername(
          u.username
        ) === username
    );

  if (user) {
    user.role =
      "superadmin";

    user.schoolId =
      null;

    user.active =
      true;

    user.updatedAt =
      now();

    saveJSON(
      USERS_FILE,
      users
    );

    console.log(
      `Superadmin ready: ${email}`
    );

    return;
  }

  const passwordHash =
    await bcrypt.hash(
      password,
      12
    );

  user = {
    id:
      id("user"),

    fullName,

    username,

    email,

    passwordHash,

    role:
      "superadmin",

    schoolId:
      null,

    profilePicture:
      "",

    provider:
      "local",

    googleId:
      "",

    active:
      true,

    createdAt:
      now(),

    updatedAt:
      now()
  };

  users.push(user);

  saveJSON(
    USERS_FILE,
    users
  );

  console.log(
    `Superadmin created: ${email}`
  );
}


// ============================================================
// DASHBOARD REDIRECT
// ============================================================

app.get(
  "/dashboard",
  (req, res) => {
    if (
      req.isAuthenticated &&
      req.isAuthenticated() &&
      req.user
    ) {
      return res.redirect(
        roleRedirect(
          req.user
        )
      );
    }

    res.redirect(
      "/login.html"
    );
  }
);


// ============================================================
// STATIC FRONTEND
// ============================================================

app.use(
  express.static(
    PUBLIC_DIR,
    {
      index:
        "index.html"
    }
  )
);


// ============================================================
// FRONTEND FALLBACK
// ============================================================

app.get(
  "*",
  (req, res, next) => {
    if (
      req.path.startsWith(
        "/api/"
      )
    ) {
      return next();
    }

    if (
      req.path.startsWith(
        "/auth/"
      )
    ) {
      return next();
    }

    const requested =
      path.join(
        PUBLIC_DIR,
        req.path
      );

    if (
      fs.existsSync(
        requested
      ) &&
      fs.statSync(
        requested
      ).isFile()
    ) {
      return res.sendFile(
        requested
      );
    }

    const indexFile =
      path.join(
        PUBLIC_DIR,
        "index.html"
      );

    if (
      fs.existsSync(
        indexFile
      )
    ) {
      return res.sendFile(
        indexFile
      );
    }

    next();
  }
);


// ============================================================
// API 404
// MUST BE AFTER ALL API ROUTES
// ============================================================

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      ok: false,
      error:
        "API route not found",
      path:
        req.originalUrl
    });
  }
);


// ============================================================
// UPLOAD ERROR HANDLER
// ============================================================

app.use(
  (error, req, res, next) => {
    if (
      error instanceof
      multer.MulterError
    ) {
      return res.status(400).json({
        ok: false,
        error:
          `Upload error: ${error.message}`
      });
    }

    if (
      error &&
      error.message &&
      error.message.includes(
        "Only JPG"
      )
    ) {
      return res.status(400).json({
        ok: false,
        error:
          error.message
      });
    }

    next(error);
  }
);


// ============================================================
// GENERAL ERROR HANDLER
// ============================================================

app.use(
  (error, req, res, next) => {
    console.error(
      "SERVER ERROR:",
      error
    );

    if (
      res.headersSent
    ) {
      return next(error);
    }

    res.status(500).json({
      ok: false,
      error:
        "Internal server error."
    });
  }
);


// ============================================================
// STARTUP
// ============================================================

let server;

async function startServer() {
  try {
    await ensureSuperadmin();

    server =
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
            `Schools: ${schools.length}`
          );
          console.log(
            `Users: ${users.length}`
          );
          console.log(
            `Subjects: ${subjects.length}`
          );
          console.log(
            `Exams: ${exams.length}`
          );
          console.log(
            `Questions: ${questions.length}`
          );
          console.log(
            "=========================================="
          );
          console.log("");
        }
      );
  } catch (error) {
    console.error(
      "Startup failed:",
      error
    );

    process.exit(1);
  }
}


// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

function shutdown(signal) {
  console.log(
    `${signal} received. Shutting down...`
  );

  try {
    saveJSON(
      USERS_FILE,
      users
    );

    saveJSON(
      SCHOOLS_FILE,
      schools
    );

    saveJSON(
      SETTINGS_FILE,
      settings
    );

    saveJSON(
      SUBJECTS_FILE,
      subjects
    );

    saveJSON(
      EXAMS_FILE,
      exams
    );

    saveJSON(
      QUESTIONS_FILE,
      questions
    );

    saveJSON(
      RESULTS_FILE,
      results
    );

    saveJSON(
      ANNOUNCEMENTS_FILE,
      announcements
    );

    sessionStore.save();
  } catch (error) {
    console.error(
      "Shutdown save error:",
      error
    );
  }

  if (server) {
    server.close(
      () => {
        console.log(
          "SchoolHub Pro stopped."
        );

        process.exit(0);
      }
    );

    setTimeout(
      () => {
        process.exit(0);
      },
      10000
    );
  } else {
    process.exit(0);
  }
}

process.on(
  "SIGTERM",
  () =>
    shutdown("SIGTERM")
);

process.on(
  "SIGINT",
  () =>
    shutdown("SIGINT")
);


// ============================================================
// START
// ============================================================

startServer();
