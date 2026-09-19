/*
===========================================================
 SCHOOLHUB PRO - COMPLETE SERVER
 Multi-School School Management + CBT Platform
===========================================================

FEATURES
- Multi-school isolation
- Superadmin
- School Admin
- Teacher
- Student
- No parent dashboard
- Local login
- Google OAuth
- Persistent file-backed sessions
- Railway persistent storage
- School branding
- School logo upload
- Profile picture upload
- User management
- Subject management
- CBT creation and management
- Question Bank
- Bulk JSON question import
- Results
- Announcements
- Dashboard summaries
- Platform settings
- Graceful Railway shutdown

REQUIRED DEPENDENCIES

npm install express express-session bcryptjs dotenv passport passport-google-oauth20 multer

===========================================================
*/

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const bcrypt = require("bcryptjs");
const multer = require("multer");
const dotenv = require("dotenv");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

dotenv.config();

/* =========================================================
   BASIC CONFIG
========================================================= */

const app = express();

const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PRODUCTION = NODE_ENV === "production";

const HOST = "0.0.0.0";

const PUBLIC_DIR = path.join(__dirname, "public");

const STORAGE_ROOT =
  process.env.STORAGE_ROOT ||
  path.join(__dirname, "storage");

const DATA_DIR = path.join(STORAGE_ROOT, "data");

const UPLOAD_DIR = path.join(STORAGE_ROOT, "uploads");
const PROFILE_UPLOAD_DIR = path.join(UPLOAD_DIR, "profile");
const BRANDING_UPLOAD_DIR = path.join(UPLOAD_DIR, "branding");

const SESSION_FILE = path.join(STORAGE_ROOT, "sessions.json");

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "schoolhub-development-session-secret-change-this";

/* Railway reverse proxy support */
if (IS_PRODUCTION) {
  app.set("trust proxy", 1);
}

/* =========================================================
   CREATE DIRECTORIES
========================================================= */

[
  STORAGE_ROOT,
  DATA_DIR,
  UPLOAD_DIR,
  PROFILE_UPLOAD_DIR,
  BRANDING_UPLOAD_DIR
].forEach((dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

/* =========================================================
   JSON FILES
========================================================= */

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

/* =========================================================
   JSON HELPERS
========================================================= */

function ensureJsonFile(file, defaultValue) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(
      file,
      JSON.stringify(defaultValue, null, 2),
      "utf8"
    );
  }
}

function readJson(file, fallback) {
  try {
    ensureJsonFile(file, fallback);

    const raw = fs.readFileSync(file, "utf8").trim();

    if (!raw) {
      return fallback;
    }

    return JSON.parse(raw);
  } catch (error) {
    console.error("JSON READ ERROR:", file, error.message);
    return fallback;
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

function getData(name) {
  return readJson(FILES[name], DEFAULTS[name]);
}

function saveData(name, data) {
  writeJson(FILES[name], data);
}

Object.entries(FILES).forEach(([name, file]) => {
  ensureJsonFile(file, DEFAULTS[name]);
});

/* =========================================================
   HELPERS
========================================================= */

function now() {
  return new Date().toISOString();
}

function makeId(prefix = "id") {
  return `${prefix}_${Date.now()}_${crypto
    .randomBytes(5)
    .toString("hex")}`;
}

function clean(value) {
  return String(value ?? "").trim();
}

function lower(value) {
  return clean(value).toLowerCase();
}

function safeUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    fullName: user.fullName,
    username: user.username,
    email: user.email,
    role: user.role,
    schoolId: user.schoolId || null,
    profilePicture: user.profilePicture || "",
    provider: user.provider || "local",
    active: user.active !== false,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
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

function isSuperadmin(user) {
  return user && user.role === "superadmin";
}

function isSchoolAdmin(user) {
  return user && user.role === "school_admin";
}

function isTeacher(user) {
  return user && user.role === "teacher";
}

function isStudent(user) {
  return user && user.role === "student";
}

function canManageSchool(user) {
  return (
    user &&
    ["superadmin", "school_admin"].includes(user.role)
  );
}

function canManageAcademicData(user) {
  return (
    user &&
    ["superadmin", "school_admin", "teacher"].includes(user.role)
  );
}

function findUserById(id) {
  const users = getData("users");
  return users.find((u) => u.id === id) || null;
}

function findSchoolById(id) {
  const schools = getData("schools");
  return schools.find((s) => s.id === id) || null;
}

function getUserSchool(req) {
  if (!req.user || !req.user.schoolId) {
    return null;
  }

  return findSchoolById(req.user.schoolId);
}

function sameSchool(user, schoolId) {
  if (!user) return false;
  if (user.role === "superadmin") return true;
  return String(user.schoolId) === String(schoolId);
}

function parseBoolean(value, fallback = false) {
  if (typeof value === "boolean") return value;

  if (value === undefined || value === null) {
    return fallback;
  }

  return ["true", "1", "yes", "on"].includes(
    String(value).toLowerCase()
  );
}

function parseDate(value) {
  if (!value) return null;

  const d = new Date(value);

  if (Number.isNaN(d.getTime())) {
    return null;
  }

  return d.toISOString();
}

function normalizeOptions(options) {
  if (Array.isArray(options)) {
    return options.map((x) => clean(x));
  }

  return [];
}

/* =========================================================
   EXPRESS MIDDLEWARE
========================================================= */

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

/* Uploaded files */
app.use(
  "/uploads",
  express.static(UPLOAD_DIR)
);

/* =========================================================
   FILE-BACKED SESSION STORE
========================================================= */

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
        fs.writeFileSync(
          this.file,
          "{}",
          "utf8"
        );
        this.sessions = {};
        return;
      }

      const raw = fs.readFileSync(
        this.file,
        "utf8"
      ).trim();

      this.sessions = raw
        ? JSON.parse(raw)
        : {};

      this.cleanup();
    } catch (error) {
      console.error(
        "SESSION STORE LOAD ERROR:",
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
        "SESSION STORE SAVE ERROR:",
        error.message
      );
    }
  }

  cleanup() {
    const currentTime = Date.now();
    let changed = false;

    for (const sid of Object.keys(this.sessions)) {
      const sess = this.sessions[sid];

      if (
        sess &&
        sess.cookie &&
        sess.cookie.expires
      ) {
        const expires =
          new Date(sess.cookie.expires).getTime();

        if (
          Number.isFinite(expires) &&
          expires <= currentTime
        ) {
          delete this.sessions[sid];
          changed = true;
        }
      }
    }

    if (changed) {
      this.save();
    }
  }

  get(sid, callback) {
    try {
      this.cleanup();

      const sess = this.sessions[sid];

      if (!sess) {
        return callback(null, null);
      }

      if (
        sess.cookie &&
        sess.cookie.expires
      ) {
        sess.cookie.expires = new Date(
          sess.cookie.expires
        );
      }

      callback(null, sess);
    } catch (error) {
      callback(error);
    }
  }

  set(sid, sess, callback) {
    try {
      this.sessions[sid] = sess;
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

  touch(sid, sess, callback) {
    try {
      this.sessions[sid] = sess;
      this.save();
      callback(null);
    } catch (error) {
      callback(error);
    }
  }
}

const sessionStore =
  new FileSessionStore(SESSION_FILE);

/* =========================================================
   SESSION
========================================================= */

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
        7 * 24 * 60 * 60 * 1000
    }
  })
);

/* =========================================================
   PASSPORT
========================================================= */

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  try {
    const user = findUserById(id);

    if (!user || user.active === false) {
      return done(null, false);
    }

    done(null, user);
  } catch (error) {
    done(error);
  }
});

/* =========================================================
   GOOGLE AUTH
========================================================= */

const GOOGLE_CLIENT_ID =
  clean(process.env.GOOGLE_CLIENT_ID);

const GOOGLE_CLIENT_SECRET =
  clean(process.env.GOOGLE_CLIENT_SECRET);

const GOOGLE_CALLBACK_URL =
  clean(
    process.env.GOOGLE_CALLBACK_URL ||
      (IS_PRODUCTION
        ? ""
        : "http://localhost:3000/auth/google/callback")
  );

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

        clientSecret:
          GOOGLE_CLIENT_SECRET,

        callbackURL:
          GOOGLE_CALLBACK_URL,

        proxy: IS_PRODUCTION
      },

      async (
        accessToken,
        refreshToken,
        profile,
        done
      ) => {
        try {
          const users = getData("users");

          const googleId =
            profile.id;

          const email =
            lower(
              profile.emails &&
                profile.emails[0]
                ? profile.emails[0].value
                : ""
            );

          let user =
            users.find(
              (u) =>
                u.googleId === googleId
            );

          if (!user && email) {
            user =
              users.find(
                (u) =>
                  lower(u.email) ===
                  email
              );
          }

          /*
            Google does not automatically create
            random school accounts.

            The user must first register
            normally in SchoolHub.
          */

          if (!user) {
            return done(
              null,
              false,
              {
                message:
                  "google_account_not_registered"
              }
            );
          }

          if (user.active === false) {
            return done(
              null,
              false,
              {
                message:
                  "account_disabled"
              }
            );
          }

          let changed = false;

          if (!user.googleId) {
            user.googleId =
              googleId;

            changed = true;
          }

          if (
            !user.profilePicture &&
            profile.photos &&
            profile.photos[0]
          ) {
            user.profilePicture =
              profile.photos[0].value;

            changed = true;
          }

          user.provider = "google";
          user.updatedAt = now();

          if (changed) {
            saveData("users", users);
          }

          done(null, user);
        } catch (error) {
          done(error);
        }
      }
    )
  );
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function requireAuth(req, res, next) {
  if (
    req.isAuthenticated &&
    req.isAuthenticated() &&
    req.user &&
    req.user.active !== false
  ) {
    return next();
  }

  return res.status(401).json({
    ok: false,
    error: "Authentication required"
  });
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (
      !req.isAuthenticated ||
      !req.isAuthenticated() ||
      !req.user
    ) {
      return res.status(401).json({
        ok: false,
        error: "Authentication required"
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        ok: false,
        error: "Permission denied"
      });
    }

    next();
  };
}

/* =========================================================
   MULTER UPLOAD
========================================================= */

const uploadStorage =
  multer.diskStorage({
    destination: (req, file, cb) => {
      if (
        req.path.includes(
          "/school/branding/logo"
        )
      ) {
        cb(
          null,
          BRANDING_UPLOAD_DIR
        );
      } else {
        cb(
          null,
          PROFILE_UPLOAD_DIR
        );
      }
    },

    filename: (req, file, cb) => {
      const ext =
        path
          .extname(file.originalname)
          .toLowerCase();

      const filename =
        `${Date.now()}-${crypto.randomUUID()}${ext}`;

      cb(null, filename);
    }
  });

const upload =
  multer({
    storage: uploadStorage,

    limits: {
      fileSize:
        5 * 1024 * 1024
    },

    fileFilter:
      (req, file, cb) => {
        const allowed = [
          "image/jpeg",
          "image/png",
          "image/webp",
          "image/gif"
        ];

        if (
          allowed.includes(
            file.mimetype
          )
        ) {
          cb(null, true);
        } else {
          cb(
            new Error(
              "Only JPG, PNG, WEBP and GIF images are allowed."
            )
          );
        }
      }
  });

/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      ok: true,
      status: "online",
      service: "SchoolHub Pro",
      version: "6.0.0",
      environment: NODE_ENV,
      port: PORT,
      storage: STORAGE_ROOT,
      googleAuth:
        googleConfigured
          ? "CONFIGURED"
          : "NOT CONFIGURED",
      sessionStore:
        "FILE",
      time: now()
    });
  }
);

/* =========================================================
   PLATFORM
========================================================= */

app.get(
  "/api/platform",
  (req, res) => {
    const settings =
      getData("settings");

    res.json({
      ok: true,
      platform: settings
    });
  }
);

app.get(
  "/api/platform-config",
  (req, res) => {
    const settings =
      getData("settings");

    res.json({
      ok: true,
      platformName:
        settings.platformName,

      platformDescription:
        settings.platformDescription,

      defaultTheme:
        settings.defaultTheme,

      maintenanceMode:
        settings.maintenanceMode,

      googleAuth:
        googleConfigured
    });
  }
);

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/me",
  (req, res) => {
    if (
      !req.isAuthenticated ||
      !req.isAuthenticated() ||
      !req.user
    ) {
      return res.json({
        ok: true,
        authenticated: false,
        user: null
      });
    }

    const user =
      findUserById(req.user.id);

    if (!user) {
      return res.json({
        ok: true,
        authenticated: false,
        user: null
      });
    }

    res.json({
      ok: true,
      authenticated: true,
      user: safeUser(user)
    });
  }
);

/* =========================================================
   REGISTER
========================================================= */

async function registerUser(req, res) {
  try {
    const {
      schoolName,
      school,
      schoolMotto,
      motto,
      fullName,
      adminName,
      username,
      email,
      password
    } = req.body;

    const finalSchoolName =
      clean(schoolName || school);

    const finalMotto =
      clean(schoolMotto || motto);

    const finalName =
      clean(fullName || adminName);

    const finalUsername =
      clean(username);

    const finalEmail =
      lower(email);

    if (
      !finalSchoolName ||
      !finalName ||
      !finalUsername ||
      !finalEmail ||
      !password
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "School name, name, username, email and password are required."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        ok: false,
        error:
          "Password must contain at least 6 characters."
      });
    }

    const users =
      getData("users");

    const schools =
      getData("schools");

    if (
      users.some(
        (u) =>
          lower(u.email) ===
          finalEmail
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
        (u) =>
          lower(u.username) ===
          lower(finalUsername)
      )
    ) {
      return res.status(409).json({
        ok: false,
        error:
          "Username is already in use."
      });
    }

    const schoolId =
      makeId("school");

    const userId =
      makeId("user");

    const passwordHash =
      await bcrypt.hash(
        password,
        12
      );

    const schoolRecord = {
      id: schoolId,

      name:
        finalSchoolName,

      motto:
        finalMotto,

      logo: "",

      primaryColor:
        "#2563eb",

      secondaryColor:
        "#16a34a",

      theme:
        "light",

      active: true,

      createdAt:
        now(),

      updatedAt:
        now()
    };

    const userRecord = {
      id: userId,

      fullName:
        finalName,

      username:
        finalUsername,

      email:
        finalEmail,

      passwordHash,

      role:
        "school_admin",

      schoolId,

      profilePicture: "",

      provider:
        "local",

      googleId: "",

      active: true,

      createdAt:
        now(),

      updatedAt:
        now()
    };

    schools.push(
      schoolRecord
    );

    users.push(
      userRecord
    );

    saveData(
      "schools",
      schools
    );

    saveData(
      "users",
      users
    );

    req.login(
      userRecord,
      (loginError) => {
        if (loginError) {
          console.error(
            "REGISTER SESSION ERROR:",
            loginError
          );

          return res.status(500).json({
            ok: false,
            error:
              "Account created but automatic login failed."
          });
        }

        req.session.save(
          (sessionError) => {
            if (sessionError) {
              console.error(
                "REGISTER SESSION SAVE ERROR:",
                sessionError
              );

              return res.status(500).json({
                ok: false,
                error:
                  "Account created but session could not be saved."
              });
            }

            res.json({
              ok: true,
              message:
                "Registration successful.",
              user:
                safeUser(userRecord),
              redirect:
                "/admin.html"
            });
          }
        );
      }
    );
  } catch (error) {
    console.error(
      "REGISTER ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      error:
        "Unable to create account."
    });
  }
}

app.post(
  "/api/register",
  registerUser
);

app.post(
  "/api/signup",
  registerUser
);

/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const identifier =
        lower(
          req.body.email ||
            req.body.username ||
            req.body.identifier
        );

      const password =
        String(
          req.body.password || ""
        );

      if (
        !identifier ||
        !password
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Email/username and password are required."
        });
      }

      const users =
        getData("users");

      const user =
        users.find(
          (u) =>
            lower(u.email) ===
              identifier ||
            lower(u.username) ===
              identifier
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
            "This account has been disabled."
        });
      }

      if (!user.passwordHash) {
        return res.status(401).json({
          ok: false,
          error:
            "This account does not have a local password. Use Google sign-in."
        });
      }

      const passwordMatch =
        await bcrypt.compare(
          password,
          user.passwordHash
        );

      if (!passwordMatch) {
        return res.status(401).json({
          ok: false,
          error:
            "Invalid username/email or password."
        });
      }

      req.login(
        user,
        (loginError) => {
          if (loginError) {
            console.error(
              "LOGIN SESSION ERROR:",
              loginError
            );

            return res.status(500).json({
              ok: false,
              error:
                "Unable to create login session."
            });
          }

          req.session.save(
            (sessionError) => {
              if (sessionError) {
                console.error(
                  "LOGIN SESSION SAVE ERROR:",
                  sessionError
                );

                return res.status(500).json({
                  ok: false,
                  error:
                    "Unable to save login session."
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
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to sign in."
      });
    }
  }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/api/logout",
  (req, res) => {
    req.logout(
      (logoutError) => {
        if (logoutError) {
          console.error(
            "LOGOUT ERROR:",
            logoutError
          );
        }

        req.session.destroy(
          (sessionError) => {
            if (sessionError) {
              console.error(
                "SESSION DESTROY ERROR:",
                sessionError
              );
            }

            res.clearCookie(
              "connect.sid",
              {
                httpOnly: true,
                secure:
                  IS_PRODUCTION,
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
      }
    );
  }
);

/* =========================================================
   GOOGLE LOGIN
========================================================= */

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
      {
        failureRedirect:
          "/login.html?error=google_failed"
      },
      (error, user, info) => {
        if (error) {
          console.error(
            "GOOGLE CALLBACK ERROR:",
            error
          );

          return res.redirect(
            "/login.html?error=google_failed"
          );
        }

        if (!user) {
          const reason =
            info &&
            info.message
              ? info.message
              : "google_failed";

          return res.redirect(
            `/login.html?error=${encodeURIComponent(
              reason
            )}`
          );
        }

        req.logIn(
          user,
          (loginError) => {
            if (loginError) {
              console.error(
                "GOOGLE LOGIN SESSION ERROR:",
                loginError
              );

              return res.redirect(
                "/login.html?error=session_failed"
              );
            }

            req.session.save(
              (sessionError) => {
                if (sessionError) {
                  console.error(
                    "GOOGLE SESSION SAVE ERROR:",
                    sessionError
                  );

                  return res.redirect(
                    "/login.html?error=session_failed"
                  );
                }

                res.redirect(
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

/* =========================================================
   PROFILE
========================================================= */

app.put(
  "/api/profile",
  requireAuth,
  (req, res) => {
    try {
      const users =
        getData("users");

      const user =
        users.find(
          (u) =>
            u.id === req.user.id
        );

      if (!user) {
        return res.status(404).json({
          ok: false,
          error:
            "User not found."
        });
      }

      if (
        req.body.fullName !==
        undefined
      ) {
        user.fullName =
          clean(
            req.body.fullName
          );
      }

      if (
        req.body.username !==
        undefined
      ) {
        const username =
          clean(
            req.body.username
          );

        const duplicate =
          users.find(
            (u) =>
              u.id !== user.id &&
              lower(u.username) ===
                lower(username)
          );

        if (duplicate) {
          return res.status(409).json({
            ok: false,
            error:
              "Username already exists."
          });
        }

        user.username =
          username;
      }

      user.updatedAt =
        now();

      saveData(
        "users",
        users
      );

      req.user = user;

      res.json({
        ok: true,
        message:
          "Profile updated.",
        user:
          safeUser(user)
      });
    } catch (error) {
      console.error(
        "PROFILE ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to update profile."
      });
    }
  }
);

/* =========================================================
   PROFILE PICTURE
========================================================= */

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

      const users =
        getData("users");

      const user =
        users.find(
          (u) =>
            u.id === req.user.id
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
        const oldFile =
          path.join(
            STORAGE_ROOT,
            user.profilePicture
              .replace(
                /^\/uploads\//,
                "uploads/"
              )
          );

        if (fs.existsSync(oldFile)) {
          try {
            fs.unlinkSync(
              oldFile
            );
          } catch {}
        }
      }

      user.profilePicture =
        `/uploads/profile/${req.file.filename}`;

      user.updatedAt =
        now();

      saveData(
        "users",
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
        "PROFILE PICTURE ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to upload profile picture."
      });
    }
  }
);

/* =========================================================
   SCHOOL
========================================================= */

app.get(
  "/api/school",
  requireAuth,
  (req, res) => {
    if (isSuperadmin(req.user)) {
      return res.json({
        ok: true,
        school: null
      });
    }

    const school =
      getUserSchool(req);

    if (!school) {
      return res.status(404).json({
        ok: false,
        error:
          "School not found."
      });
    }

    res.json({
      ok: true,
      school
    });
  }
);

app.get(
  "/api/school/branding",
  requireAuth,
  (req, res) => {
    const school =
      getUserSchool(req);

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
      }
    });
  }
);

/* =========================================================
   SCHOOL BRANDING
========================================================= */

app.put(
  "/api/school/branding",
  requireRole(
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    try {
      let school;

      if (isSuperadmin(req.user)) {
        const schoolId =
          clean(
            req.body.schoolId
          );

        school =
          findSchoolById(
            schoolId
          );
      } else {
        school =
          getUserSchool(req);
      }

      if (!school) {
        return res.status(404).json({
          ok: false,
          error:
            "School not found."
        });
      }

      const schools =
        getData("schools");

      const record =
        schools.find(
          (s) =>
            s.id === school.id
        );

      if (!record) {
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
        record.name =
          clean(req.body.name);
      }

      if (
        req.body.motto !==
        undefined
      ) {
        record.motto =
          clean(req.body.motto);
      }

      if (
        req.body.primaryColor !==
        undefined
      ) {
        record.primaryColor =
          clean(
            req.body.primaryColor
          );
      }

      if (
        req.body.secondaryColor !==
        undefined
      ) {
        record.secondaryColor =
          clean(
            req.body.secondaryColor
          );
      }

      if (
        req.body.theme !==
        undefined
      ) {
        record.theme =
          clean(req.body.theme);
      }

      record.updatedAt =
        now();

      saveData(
        "schools",
        schools
      );

      res.json({
        ok: true,
        message:
          "School branding updated.",
        school: record
      });
    } catch (error) {
      console.error(
        "BRANDING ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to update branding."
      });
    }
  }
);

/* =========================================================
   SCHOOL LOGO UPLOAD
========================================================= */

app.post(
  "/api/school/branding/logo",
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
            "Please select a logo."
        });
      }

      let school;

      if (isSuperadmin(req.user)) {
        school =
          findSchoolById(
            clean(
              req.body.schoolId
            )
          );
      } else {
        school =
          getUserSchool(req);
      }

      if (!school) {
        return res.status(404).json({
          ok: false,
          error:
            "School not found."
        });
      }

      const schools =
        getData("schools");

      const record =
        schools.find(
          (s) =>
            s.id === school.id
        );

      if (!record) {
        return res.status(404).json({
          ok: false,
          error:
            "School not found."
        });
      }

      if (
        record.logo &&
        record.logo.startsWith(
          "/uploads/"
        )
      ) {
        const oldFile =
          path.join(
            STORAGE_ROOT,
            record.logo.replace(
              /^\/uploads\//,
              "uploads/"
            )
          );

        if (fs.existsSync(oldFile)) {
          try {
            fs.unlinkSync(
              oldFile
            );
          } catch {}
        }
      }

      record.logo =
        `/uploads/branding/${req.file.filename}`;

      record.updatedAt =
        now();

      saveData(
        "schools",
        schools
      );

      res.json({
        ok: true,
        message:
          "School logo uploaded.",
        logo:
          record.logo,
        school: record
      });
    } catch (error) {
      console.error(
        "LOGO UPLOAD ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to upload school logo."
      });
    }
  }
);

/* =========================================================
   USERS
========================================================= */

app.get(
  "/api/users",
  requireRole(
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    const users =
      getData("users");

    let result;

    if (isSuperadmin(req.user)) {
      result =
        users.map(
          (user) => safeUser(user)
        );
    } else {
      result =
        users
          .filter(
            (user) =>
              user.schoolId ===
              req.user.schoolId
          )
          .map(
            (user) =>
              safeUser(user)
          );
    }

    res.json({
      ok: true,
      users: result
    });
  }
);

/* =========================================================
   CREATE USER
========================================================= */

app.post(
  "/api/users",
  requireRole(
    "school_admin",
    "superadmin"
  ),
  async (req, res) => {
    try {
      const users =
        getData("users");

      const {
        fullName,
        username,
        email,
        password,
        role,
        schoolId
      } = req.body;

      const finalName =
        clean(fullName);

      const finalUsername =
        clean(username);

      const finalEmail =
        lower(email);

      if (
        !finalName ||
        !finalUsername ||
        !finalEmail ||
        !password
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Name, username, email and password are required."
        });
      }

      if (
        users.some(
          (u) =>
            lower(u.email) ===
            finalEmail
        )
      ) {
        return res.status(409).json({
          ok: false,
          error:
            "Email already exists."
        });
      }

      if (
        users.some(
          (u) =>
            lower(u.username) ===
            lower(finalUsername)
        )
      ) {
        return res.status(409).json({
          ok: false,
          error:
            "Username already exists."
        });
      }

      let finalSchoolId;

      if (isSuperadmin(req.user)) {
        finalSchoolId =
          clean(schoolId) || null;
      } else {
        finalSchoolId =
          req.user.schoolId;
      }

      if (
        !finalSchoolId
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "A school is required."
        });
      }

      if (
        !findSchoolById(
          finalSchoolId
        )
      ) {
        return res.status(404).json({
          ok: false,
          error:
            "School not found."
        });
      }

      let finalRole =
        clean(role);

      /*
        School admins can only create
        teachers and students.
      */

      if (
        isSchoolAdmin(req.user)
      ) {
        if (
          ![
            "teacher",
            "student"
          ].includes(finalRole)
        ) {
          return res.status(403).json({
            ok: false,
            error:
              "School admins can only create teachers and students."
          });
        }
      }

      if (
        isSuperadmin(req.user)
      ) {
        if (
          ![
            "school_admin",
            "teacher",
            "student"
          ].includes(finalRole)
        ) {
          return res.status(400).json({
            ok: false,
            error:
              "Invalid user role."
          });
        }
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const user = {
        id:
          makeId("user"),

        fullName:
          finalName,

        username:
          finalUsername,

        email:
          finalEmail,

        passwordHash,

        role:
          finalRole,

        schoolId:
          finalSchoolId,

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

      saveData(
        "users",
        users
      );

      res.status(201).json({
        ok: true,
        message:
          "User created successfully.",
        user:
          safeUser(user)
      });
    } catch (error) {
      console.error(
        "CREATE USER ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to create user."
      });
    }
  }
);

/* =========================================================
   UPDATE USER
========================================================= */

app.put(
  "/api/users/:id",
  requireRole(
    "school_admin",
    "superadmin"
  ),
  async (req, res) => {
    try {
      const users =
        getData("users");

      const user =
        users.find(
          (u) =>
            u.id ===
            req.params.id
        );

      if (!user) {
        return res.status(404).json({
          ok: false,
          error:
            "User not found."
        });
      }

      if (
        !isSuperadmin(req.user) &&
        user.schoolId !==
          req.user.schoolId
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
          clean(
            req.body.fullName
          );
      }

      if (
        req.body.username !==
        undefined
      ) {
        const username =
          clean(
            req.body.username
          );

        const duplicate =
          users.find(
            (u) =>
              u.id !== user.id &&
              lower(u.username) ===
                lower(username)
          );

        if (duplicate) {
          return res.status(409).json({
            ok: false,
            error:
              "Username already exists."
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
          lower(
            req.body.email
          );

        const duplicate =
          users.find(
            (u) =>
              u.id !== user.id &&
              lower(u.email) ===
                email
          );

        if (duplicate) {
          return res.status(409).json({
            ok: false,
            error:
              "Email already exists."
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
          isSchoolAdmin(req.user)
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
          isSuperadmin(req.user) &&
          [
            "school_admin",
            "teacher",
            "student"
          ].includes(
            req.body.role
          )
        ) {
          user.role =
            req.body.role;
        }
      }

      if (
        req.body.active !==
        undefined
      ) {
        user.active =
          parseBoolean(
            req.body.active,
            true
          );
      }

      if (
        req.body.password
      ) {
        user.passwordHash =
          await bcrypt.hash(
            req.body.password,
            12
          );
      }

      user.updatedAt =
        now();

      saveData(
        "users",
        users
      );

      res.json({
        ok: true,
        message:
          "User updated.",
        user:
          safeUser(user)
      });
    } catch (error) {
      console.error(
        "UPDATE USER ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to update user."
      });
    }
  }
);

/* =========================================================
   DELETE / DEACTIVATE USER
========================================================= */

app.delete(
  "/api/users/:id",
  requireRole(
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    try {
      const users =
        getData("users");

      const user =
        users.find(
          (u) =>
            u.id ===
            req.params.id
        );

      if (!user) {
        return res.status(404).json({
          ok: false,
          error:
            "User not found."
        });
      }

      if (
        user.id ===
        req.user.id
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "You cannot delete your own account."
        });
      }

      if (
        !isSuperadmin(req.user) &&
        user.schoolId !==
          req.user.schoolId
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "Permission denied."
        });
      }

      user.active = false;
      user.updatedAt = now();

      saveData(
        "users",
        users
      );

      res.json({
        ok: true,
        message:
          "User deactivated."
      });
    } catch (error) {
      console.error(
        "DELETE USER ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to deactivate user."
      });
    }
  }
);

/* =========================================================
   SUBJECTS
========================================================= */

app.get(
  "/api/subjects",
  requireAuth,
  (req, res) => {
    const subjects =
      getData("subjects");

    let result;

    if (isSuperadmin(req.user)) {
      result =
        subjects;
    } else {
      result =
        subjects.filter(
          (s) =>
            s.schoolId ===
            req.user.schoolId
        );
    }

    res.json({
      ok: true,
      subjects: result
    });
  }
);

app.post(
  "/api/subjects",
  requireRole(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    try {
      const subjects =
        getData("subjects");

      const {
        name,
        code,
        description,
        schoolId,
        teacherIds
      } = req.body;

      const finalName =
        clean(name);

      if (!finalName) {
        return res.status(400).json({
          ok: false,
          error:
            "Subject name is required."
        });
      }

      let finalSchoolId;

      if (isSuperadmin(req.user)) {
        finalSchoolId =
          clean(schoolId);
      } else {
        finalSchoolId =
          req.user.schoolId;
      }

      if (
        !finalSchoolId ||
        !findSchoolById(
          finalSchoolId
        )
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Valid school is required."
        });
      }

      const subject = {
        id:
          makeId("subject"),

        schoolId:
          finalSchoolId,

        name:
          finalName,

        code:
          clean(code),

        description:
          clean(description),

        teacherIds:
          Array.isArray(
            teacherIds
          )
            ? teacherIds
            : isTeacher(req.user)
              ? [req.user.id]
              : [],

        active:
          true,

        createdAt:
          now(),

        updatedAt:
          now()
      };

      subjects.push(
        subject
      );

      saveData(
        "subjects",
        subjects
      );

      res.status(201).json({
        ok: true,
        subject
      });
    } catch (error) {
      console.error(
        "CREATE SUBJECT ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to create subject."
      });
    }
  }
);

app.put(
  "/api/subjects/:id",
  requireRole(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const subjects =
      getData("subjects");

    const subject =
      subjects.find(
        (s) =>
          s.id ===
          req.params.id
      );

    if (!subject) {
      return res.status(404).json({
        ok: false,
        error:
          "Subject not found."
      });
    }

    if (
      !isSuperadmin(req.user) &&
      subject.schoolId !==
        req.user.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Permission denied."
      });
    }

    if (
      req.body.name !==
      undefined
    ) {
      subject.name =
        clean(req.body.name);
    }

    if (
      req.body.code !==
      undefined
    ) {
      subject.code =
        clean(req.body.code);
    }

    if (
      req.body.description !==
      undefined
    ) {
      subject.description =
        clean(
          req.body.description
        );
    }

    if (
      Array.isArray(
        req.body.teacherIds
      ) &&
      canManageSchool(req.user)
    ) {
      subject.teacherIds =
        req.body.teacherIds;
    }

    if (
      req.body.active !==
      undefined
    ) {
      subject.active =
        parseBoolean(
          req.body.active,
          true
        );
    }

    subject.updatedAt =
      now();

    saveData(
      "subjects",
      subjects
    );

    res.json({
      ok: true,
      subject
    });
  }
);

app.delete(
  "/api/subjects/:id",
  requireRole(
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    const subjects =
      getData("subjects");

    const index =
      subjects.findIndex(
        (s) =>
          s.id ===
          req.params.id
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
      !isSuperadmin(req.user) &&
      subject.schoolId !==
        req.user.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Permission denied."
      });
    }

    subjects.splice(
      index,
      1
    );

    saveData(
      "subjects",
      subjects
    );

    res.json({
      ok: true,
      message:
        "Subject deleted."
    });
  }
);

/* =========================================================
   QUESTIONS - QUESTION BANK
========================================================= */

function questionBelongsToUserSchool(
  question,
  user
) {
  return (
    isSuperadmin(user) ||
    question.schoolId ===
      user.schoolId
  );
}

/* GET QUESTION BANK */

app.get(
  "/api/questions",
  requireAuth,
  (req, res) => {
    try {
      let questions =
        getData("questions");

      if (!isSuperadmin(req.user)) {
        questions =
          questions.filter(
            (q) =>
              q.schoolId ===
              req.user.schoolId
          );
      }

      const {
        subjectId,
        examId,
        difficulty,
        search,
        q
      } = req.query;

      const searchTerm =
        lower(search || q);

      if (subjectId) {
        questions =
          questions.filter(
            (item) =>
              item.subjectId ===
              subjectId
          );
      }

      if (examId) {
        questions =
          questions.filter(
            (item) =>
              item.examId ===
              examId
          );
      }

      if (difficulty) {
        questions =
          questions.filter(
            (item) =>
              lower(
                item.difficulty
              ) ===
              lower(difficulty)
          );
      }

      if (searchTerm) {
        questions =
          questions.filter(
            (item) =>
              lower(
                item.question
              ).includes(
                searchTerm
              ) ||
              lower(
                item.tags
              ).includes(
                searchTerm
              )
          );
      }

      /*
        Students should not receive
        correct answers while browsing.
      */

      if (isStudent(req.user)) {
        questions =
          questions.map(
            ({
              answer,
              ...safeQuestion
            }) =>
              safeQuestion
          );
      }

      res.json({
        ok: true,
        questions,
        total:
          questions.length
      });
    } catch (error) {
      console.error(
        "GET QUESTIONS ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to load question bank."
      });
    }
  }
);

/* ADD QUESTION */

app.post(
  "/api/questions",
  requireRole(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    try {
      const questions =
        getData("questions");

      const {
        question,
        options,
        answer,
        points,
        difficulty,
        tags,
        subjectId,
        examId,
        schoolId
      } = req.body;

      const finalQuestion =
        clean(question);

      const finalOptions =
        normalizeOptions(
          options
        );

      if (
        !finalQuestion ||
        finalOptions.length <
          2
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Question and at least two options are required."
        });
      }

      let finalSchoolId;

      if (isSuperadmin(req.user)) {
        finalSchoolId =
          clean(schoolId);
      } else {
        finalSchoolId =
          req.user.schoolId;
      }

      if (
        !finalSchoolId ||
        !findSchoolById(
          finalSchoolId
        )
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Valid school is required."
        });
      }

      const answerIndex =
        Number(answer);

      if (
        !Number.isInteger(
          answerIndex
        ) ||
        answerIndex < 0 ||
        answerIndex >=
          finalOptions.length
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Answer must be a valid option index."
        });
      }

      const item = {
        id:
          makeId("question"),

        schoolId:
          finalSchoolId,

        subjectId:
          clean(subjectId),

        examId:
          clean(examId),

        question:
          finalQuestion,

        options:
          finalOptions,

        answer:
          answerIndex,

        points:
          Math.max(
            1,
            Number(points) || 1
          ),

        difficulty:
          clean(
            difficulty
          ) || "medium",

        tags:
          clean(tags),

        active:
          true,

        createdBy:
          req.user.id,

        createdAt:
          now(),

        updatedAt:
          now()
      };

      questions.push(
        item
      );

      saveData(
        "questions",
        questions
      );

      /*
        If attached to an exam,
        automatically add question ID.
      */

      if (item.examId) {
        const exams =
          getData("exams");

        const exam =
          exams.find(
            (e) =>
              e.id ===
              item.examId
          );

        if (
          exam &&
          exam.schoolId ===
            item.schoolId
        ) {
          exam.questionIds =
            Array.isArray(
              exam.questionIds
            )
              ? exam.questionIds
              : [];

          if (
            !exam.questionIds.includes(
              item.id
            )
          ) {
            exam.questionIds.push(
              item.id
            );
          }

          exam.updatedAt =
            now();

          saveData(
            "exams",
            exams
          );
        }
      }

      res.status(201).json({
        ok: true,
        message:
          "Question added successfully.",
        question: item
      });
    } catch (error) {
      console.error(
        "ADD QUESTION ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to add question."
      });
    }
  }
);

/* =========================================================
   BULK JSON QUESTION IMPORT
========================================================= */

app.post(
  "/api/questions/bulk",
  requireRole(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    try {
      const questions =
        getData("questions");

      let input =
        req.body.questions;

      if (
        typeof input ===
        "string"
      ) {
        try {
          input =
            JSON.parse(input);
        } catch {
          return res.status(400).json({
            ok: false,
            error:
              "Invalid JSON."
          });
        }
      }

      if (!Array.isArray(input)) {
        return res.status(400).json({
          ok: false,
          error:
            "questions must be an array."
        });
      }

      let schoolId;

      if (isSuperadmin(req.user)) {
        schoolId =
          clean(
            req.body.schoolId
          );
      } else {
        schoolId =
          req.user.schoolId;
      }

      if (
        !schoolId ||
        !findSchoolById(
          schoolId
        )
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Valid school is required."
        });
      }

      const imported = [];
      const errors = [];

      input.forEach(
        (raw, index) => {
          const questionText =
            clean(
              raw.question
            );

          const options =
            normalizeOptions(
              raw.options
            );

          const answer =
            Number(
              raw.answer
            );

          if (
            !questionText ||
            options.length < 2
          ) {
            errors.push({
              index,
              error:
                "Question and at least two options are required."
            });

            return;
          }

          if (
            !Number.isInteger(
              answer
            ) ||
            answer < 0 ||
            answer >=
              options.length
          ) {
            errors.push({
              index,
              error:
                "Invalid answer index."
            });

            return;
          }

          const item = {
            id:
              makeId(
                "question"
              ),

            schoolId,

            subjectId:
              clean(
                raw.subjectId
              ),

            examId:
              clean(
                raw.examId
              ),

            question:
              questionText,

            options,

            answer,

            points:
              Math.max(
                1,
                Number(
                  raw.points
                ) || 1
              ),

            difficulty:
              clean(
                raw.difficulty
              ) || "medium",

            tags:
              clean(raw.tags),

            active:
              true,

            createdBy:
              req.user.id,

            createdAt:
              now(),

            updatedAt:
              now()
          };

          questions.push(
            item
          );

          imported.push(
            item
          );
        }
      );

      saveData(
        "questions",
        questions
      );

      /*
        Attach imported questions
        to exams where applicable.
      */

      const exams =
        getData("exams");

      let examsChanged =
        false;

      imported.forEach(
        (question) => {
          if (!question.examId) {
            return;
          }

          const exam =
            exams.find(
              (e) =>
                e.id ===
                  question.examId &&
                e.schoolId ===
                  question.schoolId
            );

          if (!exam) {
            return;
          }

          exam.questionIds =
            Array.isArray(
              exam.questionIds
            )
              ? exam.questionIds
              : [];

          if (
            !exam.questionIds.includes(
              question.id
            )
          ) {
            exam.questionIds.push(
              question.id
            );

            exam.updatedAt =
              now();

            examsChanged = true;
          }
        }
      );

      if (examsChanged) {
        saveData(
          "exams",
          exams
        );
      }

      res.json({
        ok: true,

        message:
          `${imported.length} question(s) imported.`,

        imported:
          imported.length,

        failed:
          errors.length,

        errors
      });
    } catch (error) {
      console.error(
        "BULK QUESTION ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to import questions."
      });
    }
  }
);

/* =========================================================
   UPDATE QUESTION
========================================================= */

app.put(
  "/api/questions/:id",
  requireRole(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const questions =
      getData("questions");

    const item =
      questions.find(
        (q) =>
          q.id ===
          req.params.id
      );

    if (!item) {
      return res.status(404).json({
        ok: false,
        error:
          "Question not found."
      });
    }

    if (
      !questionBelongsToUserSchool(
        item,
        req.user
      )
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Permission denied."
      });
    }

    if (
      req.body.question !==
      undefined
    ) {
      item.question =
        clean(
          req.body.question
        );
    }

    if (
      req.body.options !==
      undefined
    ) {
      item.options =
        normalizeOptions(
          req.body.options
        );
    }

    if (
      req.body.answer !==
      undefined
    ) {
      item.answer =
        Number(
          req.body.answer
        );
    }

    if (
      req.body.points !==
      undefined
    ) {
      item.points =
        Math.max(
          1,
          Number(
            req.body.points
          ) || 1
        );
    }

    if (
      req.body.difficulty !==
      undefined
    ) {
      item.difficulty =
        clean(
          req.body.difficulty
        );
    }

    if (
      req.body.tags !==
      undefined
    ) {
      item.tags =
        clean(
          req.body.tags
        );
    }

    if (
      req.body.subjectId !==
      undefined
    ) {
      item.subjectId =
        clean(
          req.body.subjectId
        );
    }

    if (
      req.body.examId !==
      undefined
    ) {
      item.examId =
        clean(
          req.body.examId
        );
    }

    if (
      req.body.active !==
      undefined
    ) {
      item.active =
        parseBoolean(
          req.body.active,
          true
        );
    }

    item.updatedAt =
      now();

    saveData(
      "questions",
      questions
    );

    res.json({
      ok: true,
      question: item
    });
  }
);

/* =========================================================
   DELETE QUESTION
========================================================= */

app.delete(
  "/api/questions/:id",
  requireRole(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const questions =
      getData("questions");

    const index =
      questions.findIndex(
        (q) =>
          q.id ===
          req.params.id
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error:
          "Question not found."
      });
    }

    const item =
      questions[index];

    if (
      !questionBelongsToUserSchool(
        item,
        req.user
      )
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Permission denied."
      });
    }

    questions.splice(
      index,
      1
    );

    saveData(
      "questions",
      questions
    );

    /*
      Remove question from
      exam questionIds.
    */

    if (item.examId) {
      const exams =
        getData("exams");

      const exam =
        exams.find(
          (e) =>
            e.id ===
            item.examId
        );

      if (exam) {
        exam.questionIds =
          (
            exam.questionIds ||
            []
          ).filter(
            (id) =>
              id !== item.id
          );

        exam.updatedAt =
          now();

        saveData(
          "exams",
          exams
        );
      }
    }

    res.json({
      ok: true,
      message:
        "Question deleted."
    });
  }
);

/* =========================================================
   EXAMS / CBT
========================================================= */

app.get(
  "/api/exams",
  requireAuth,
  (req, res) => {
    let exams =
      getData("exams");

    if (!isSuperadmin(req.user)) {
      exams =
        exams.filter(
          (exam) =>
            exam.schoolId ===
            req.user.schoolId
        );
    }

    if (req.query.subjectId) {
      exams =
        exams.filter(
          (exam) =>
            exam.subjectId ===
            req.query.subjectId
        );
    }

    res.json({
      ok: true,
      exams
    });
  }
);

/* CREATE EXAM */

app.post(
  "/api/exams",
  requireRole(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    try {
      const exams =
        getData("exams");

      const {
        title,
        subjectId,
        description,
        durationMinutes,
        instructions,
        startAt,
        endAt,
        status,
        schoolId,
        questionIds
      } = req.body;

      const finalTitle =
        clean(title);

      if (!finalTitle) {
        return res.status(400).json({
          ok: false,
          error:
            "Exam title is required."
        });
      }

      let finalSchoolId;

      if (isSuperadmin(req.user)) {
        finalSchoolId =
          clean(schoolId);
      } else {
        finalSchoolId =
          req.user.schoolId;
      }

      if (
        !finalSchoolId ||
        !findSchoolById(
          finalSchoolId
        )
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Valid school is required."
        });
      }

      const exam = {
        id:
          makeId("exam"),

        schoolId:
          finalSchoolId,

        title:
          finalTitle,

        subjectId:
          clean(subjectId),

        description:
          clean(description),

        durationMinutes:
          Math.max(
            1,
            Number(
              durationMinutes
            ) || 30
          ),

        instructions:
          clean(instructions),

        startAt:
          parseDate(startAt),

        endAt:
          parseDate(endAt),

        status:
          clean(status) ||
          "draft",

        questionIds:
          Array.isArray(
            questionIds
          )
            ? questionIds
            : [],

        createdBy:
          req.user.id,

        active:
          true,

        createdAt:
          now(),

        updatedAt:
          now()
      };

      exams.push(
        exam
      );

      saveData(
        "exams",
        exams
      );

      res.status(201).json({
        ok: true,
        message:
          "CBT created successfully.",
        exam
      });
    } catch (error) {
      console.error(
        "CREATE EXAM ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to create CBT."
      });
    }
  }
);

/* UPDATE EXAM */

app.put(
  "/api/exams/:id",
  requireRole(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const exams =
      getData("exams");

    const exam =
      exams.find(
        (e) =>
          e.id ===
          req.params.id
      );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        error:
          "Exam not found."
      });
    }

    if (
      !isSuperadmin(req.user) &&
      exam.schoolId !==
        req.user.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Permission denied."
      });
    }

    const fields = [
      "title",
      "subjectId",
      "description",
      "instructions",
      "status"
    ];

    fields.forEach(
      (field) => {
        if (
          req.body[field] !==
          undefined
        ) {
          exam[field] =
            clean(
              req.body[field]
            );
        }
      }
    );

    if (
      req.body.durationMinutes !==
      undefined
    ) {
      exam.durationMinutes =
        Math.max(
          1,
          Number(
            req.body.durationMinutes
          ) || 30
        );
    }

    if (
      req.body.startAt !==
      undefined
    ) {
      exam.startAt =
        parseDate(
          req.body.startAt
        );
    }

    if (
      req.body.endAt !==
      undefined
    ) {
      exam.endAt =
        parseDate(
          req.body.endAt
        );
    }

    if (
      Array.isArray(
        req.body.questionIds
      )
    ) {
      exam.questionIds =
        req.body.questionIds;
    }

    if (
      req.body.active !==
      undefined
    ) {
      exam.active =
        parseBoolean(
          req.body.active,
          true
        );
    }

    exam.updatedAt =
      now();

    saveData(
      "exams",
      exams
    );

    res.json({
      ok: true,
      exam
    });
  }
);

/* DELETE EXAM */

app.delete(
  "/api/exams/:id",
  requireRole(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const exams =
      getData("exams");

    const index =
      exams.findIndex(
        (e) =>
          e.id ===
          req.params.id
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
      !isSuperadmin(req.user) &&
      exam.schoolId !==
        req.user.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Permission denied."
      });
    }

    exams.splice(
      index,
      1
    );

    saveData(
      "exams",
      exams
    );

    res.json({
      ok: true,
      message:
        "CBT deleted."
    });
  }
);

/* =========================================================
   START CBT
========================================================= */

app.post(
  "/api/exams/:id/start",
  requireRole("student"),
  (req, res) => {
    const exams =
      getData("exams");

    const exam =
      exams.find(
        (e) =>
          e.id ===
            req.params.id &&
          e.schoolId ===
            req.user.schoolId
      );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        error:
          "Exam not found."
      });
    }

    if (exam.active === false) {
      return res.status(403).json({
        ok: false,
        error:
          "This exam is inactive."
      });
    }

    const current =
      Date.now();

    if (
      exam.startAt &&
      new Date(
        exam.startAt
      ).getTime() >
        current
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "This exam has not started."
      });
    }

    if (
      exam.endAt &&
      new Date(
        exam.endAt
      ).getTime() <
        current
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "This exam has ended."
      });
    }

    const questions =
      getData("questions");

    const examQuestions =
      questions
        .filter(
          (q) =>
            q.schoolId ===
              req.user.schoolId &&
            (
              exam.questionIds ||
              []
            ).includes(q.id) &&
            q.active !== false
        )
        .map(
          ({
            answer,
            ...question
          }) =>
            question
        );

    res.json({
      ok: true,

      exam: {
        id: exam.id,
        title: exam.title,
        subjectId:
          exam.subjectId,
        description:
          exam.description,
        durationMinutes:
          exam.durationMinutes,
        instructions:
          exam.instructions
      },

      questions:
        examQuestions
    });
  }
);

/* =========================================================
   SUBMIT CBT
========================================================= */

app.post(
  "/api/exams/:id/submit",
  requireRole("student"),
  (req, res) => {
    try {
      const exams =
        getData("exams");

      const exam =
        exams.find(
          (e) =>
            e.id ===
              req.params.id &&
            e.schoolId ===
              req.user.schoolId
        );

      if (!exam) {
        return res.status(404).json({
          ok: false,
          error:
            "Exam not found."
        });
      }

      const existingResults =
        getData("results");

      const alreadySubmitted =
        existingResults.some(
          (result) =>
            result.examId ===
              exam.id &&
            result.studentId ===
              req.user.id
        );

      if (alreadySubmitted) {
        return res.status(409).json({
          ok: false,
          error:
            "You have already submitted this exam."
        });
      }

      const answers =
        req.body.answers || {};

      const questions =
        getData("questions");

      const examQuestions =
        questions.filter(
          (q) =>
            q.schoolId ===
              req.user.schoolId &&
            (
              exam.questionIds ||
              []
            ).includes(q.id) &&
            q.active !== false
        );

      let score = 0;
      let totalPoints = 0;

      examQuestions.forEach(
        (question) => {
          const points =
            Number(
              question.points
            ) || 1;

          totalPoints +=
            points;

          const submitted =
            answers[
              question.id
            ];

          if (
            Number(submitted) ===
            Number(
              question.answer
            )
          ) {
            score +=
              points;
          }
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
        id:
          makeId("result"),

        schoolId:
          req.user.schoolId,

        examId:
          exam.id,

        studentId:
          req.user.id,

        score,

        totalPoints,

        percentage,

        answers,

        submittedAt:
          now(),

        createdAt:
          now()
      };

      existingResults.push(
        result
      );

      saveData(
        "results",
        existingResults
      );

      res.json({
        ok: true,

        message:
          "Exam submitted successfully.",

        result: {
          id:
            result.id,

          score:
            result.score,

          totalPoints:
            result.totalPoints,

          percentage:
            result.percentage
        }
      });
    } catch (error) {
      console.error(
        "SUBMIT EXAM ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to submit exam."
      });
    }
  }
);

/* =========================================================
   RESULTS
========================================================= */

app.get(
  "/api/results",
  requireAuth,
  (req, res) => {
    let results =
      getData("results");

    if (isSuperadmin(req.user)) {
      return res.json({
        ok: true,
        results
      });
    }

    results =
      results.filter(
        (result) =>
          result.schoolId ===
          req.user.schoolId
      );

    if (isStudent(req.user)) {
      results =
        results.filter(
          (result) =>
            result.studentId ===
            req.user.id
        );
    }

    if (
      req.query.studentId &&
      canManageSchool(req.user)
    ) {
      results =
        results.filter(
          (result) =>
            result.studentId ===
            req.query.studentId
        );
    }

    if (req.query.examId) {
      results =
        results.filter(
          (result) =>
            result.examId ===
            req.query.examId
        );
    }

    res.json({
      ok: true,
      results
    });
  }
);

/* =========================================================
   ANNOUNCEMENTS
========================================================= */

app.get(
  "/api/announcements",
  requireAuth,
  (req, res) => {
    let announcements =
      getData(
        "announcements"
      );

    if (!isSuperadmin(req.user)) {
      announcements =
        announcements.filter(
          (item) =>
            item.schoolId ===
            req.user.schoolId
        );
    }

    if (req.query.audience) {
      announcements =
        announcements.filter(
          (item) =>
            item.audience ===
              req.query.audience ||
            item.audience ===
              "all"
        );
    }

    res.json({
      ok: true,
      announcements
    });
  }
);

app.post(
  "/api/announcements",
  requireRole(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    try {
      const announcements =
        getData(
          "announcements"
        );

      const {
        title,
        message,
        audience,
        schoolId
      } = req.body;

      let finalSchoolId;

      if (isSuperadmin(req.user)) {
        finalSchoolId =
          clean(schoolId);
      } else {
        finalSchoolId =
          req.user.schoolId;
      }

      if (
        !finalSchoolId
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "School is required."
        });
      }

      const item = {
        id:
          makeId(
            "announcement"
          ),

        schoolId:
          finalSchoolId,

        title:
          clean(title),

        message:
          clean(message),

        audience:
          clean(audience) ||
          "all",

        createdBy:
          req.user.id,

        createdAt:
          now(),

        updatedAt:
          now()
      };

      if (
        !item.title ||
        !item.message
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Title and message are required."
        });
      }

      announcements.push(
        item
      );

      saveData(
        "announcements",
        announcements
      );

      res.status(201).json({
        ok: true,
        announcement:
          item
      });
    } catch (error) {
      console.error(
        "CREATE ANNOUNCEMENT ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Unable to create announcement."
      });
    }
  }
);

app.put(
  "/api/announcements/:id",
  requireRole(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const announcements =
      getData(
        "announcements"
      );

    const item =
      announcements.find(
        (a) =>
          a.id ===
          req.params.id
      );

    if (!item) {
      return res.status(404).json({
        ok: false,
        error:
          "Announcement not found."
      });
    }

    if (
      !isSuperadmin(req.user) &&
      item.schoolId !==
        req.user.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Permission denied."
      });
    }

    if (
      req.body.title !==
      undefined
    ) {
      item.title =
        clean(
          req.body.title
        );
    }

    if (
      req.body.message !==
      undefined
    ) {
      item.message =
        clean(
          req.body.message
        );
    }

    if (
      req.body.audience !==
      undefined
    ) {
      item.audience =
        clean(
          req.body.audience
        );
    }

    item.updatedAt =
      now();

    saveData(
      "announcements",
      announcements
    );

    res.json({
      ok: true,
      announcement:
        item
    });
  }
);

app.delete(
  "/api/announcements/:id",
  requireRole(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const announcements =
      getData(
        "announcements"
      );

    const index =
      announcements.findIndex(
        (a) =>
          a.id ===
          req.params.id
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error:
          "Announcement not found."
      });
    }

    const item =
      announcements[index];

    if (
      !isSuperadmin(req.user) &&
      item.schoolId !==
        req.user.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Permission denied."
      });
    }

    announcements.splice(
      index,
      1
    );

    saveData(
      "announcements",
      announcements
    );

    res.json({
      ok: true,
      message:
        "Announcement deleted."
    });
  }
);

/* =========================================================
   SCHOOL ADMIN SUMMARY
========================================================= */

app.get(
  "/api/admin/summary",
  requireRole(
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    const users =
      getData("users");

    const schools =
      getData("schools");

    const subjects =
      getData("subjects");

    const exams =
      getData("exams");

    const questions =
      getData("questions");

    const results =
      getData("results");

    let schoolId =
      isSuperadmin(req.user)
        ? null
        : req.user.schoolId;

    if (
      isSuperadmin(req.user) &&
      req.query.schoolId
    ) {
      schoolId =
        req.query.schoolId;
    }

    const scopedUsers =
      schoolId
        ? users.filter(
            (u) =>
              u.schoolId ===
              schoolId
          )
        : users;

    const scopedSubjects =
      schoolId
        ? subjects.filter(
            (s) =>
              s.schoolId ===
              schoolId
          )
        : subjects;

    const scopedExams =
      schoolId
        ? exams.filter(
            (e) =>
              e.schoolId ===
              schoolId
          )
        : exams;

    const scopedQuestions =
      schoolId
        ? questions.filter(
            (q) =>
              q.schoolId ===
              schoolId
          )
        : questions;

    const scopedResults =
      schoolId
        ? results.filter(
            (r) =>
              r.schoolId ===
              schoolId
          )
        : results;

    res.json({
      ok: true,

      summary: {
        schools:
          schoolId
            ? 1
            : schools.length,

        users:
          scopedUsers.length,

        students:
          scopedUsers.filter(
            (u) =>
              u.role ===
              "student"
          ).length,

        teachers:
          scopedUsers.filter(
            (u) =>
              u.role ===
              "teacher"
          ).length,

        admins:
          scopedUsers.filter(
            (u) =>
              u.role ===
              "school_admin"
          ).length,

        subjects:
          scopedSubjects.length,

        exams:
          scopedExams.length,

        questions:
          scopedQuestions.length,

        results:
          scopedResults.length
      }
    });
  }
);

/* =========================================================
   TEACHER SUMMARY
========================================================= */

app.get(
  "/api/teacher/summary",
  requireRole("teacher"),
  (req, res) => {
    const subjects =
      getData("subjects");

    const exams =
      getData("exams");

    const questions =
      getData("questions");

    const announcements =
      getData(
        "announcements"
      );

    const mySubjects =
      subjects.filter(
        (subject) =>
          subject.schoolId ===
            req.user.schoolId &&
          (
            subject.teacherIds ||
            []
          ).includes(
            req.user.id
          )
      );

    const schoolExams =
      exams.filter(
        (exam) =>
          exam.schoolId ===
          req.user.schoolId
      );

    const schoolQuestions =
      questions.filter(
        (question) =>
          question.schoolId ===
          req.user.schoolId
      );

    const schoolAnnouncements =
      announcements.filter(
        (item) =>
          item.schoolId ===
          req.user.schoolId
      );

    res.json({
      ok: true,

      summary: {
        subjects:
          mySubjects.length,

        exams:
          schoolExams.length,

        questions:
          schoolQuestions.length,

        announcements:
          schoolAnnouncements.length
      }
    });
  }
);

/* =========================================================
   STUDENT SUMMARY
========================================================= */

app.get(
  "/api/student/summary",
  requireRole("student"),
  (req, res) => {
    const exams =
      getData("exams");

    const results =
      getData("results");

    const announcements =
      getData(
        "announcements"
      );

    const schoolExams =
      exams.filter(
        (exam) =>
          exam.schoolId ===
            req.user.schoolId &&
          exam.active !== false
      );

    const myResults =
      results.filter(
        (result) =>
          result.schoolId ===
            req.user.schoolId &&
          result.studentId ===
            req.user.id
      );

    const schoolAnnouncements =
      announcements.filter(
        (item) =>
          item.schoolId ===
          req.user.schoolId
      );

    res.json({
      ok: true,

      summary: {
        availableExams:
          schoolExams.length,

        completedExams:
          myResults.length,

        announcements:
          schoolAnnouncements.length,

        averageScore:
          myResults.length
            ? Number(
                (
                  myResults.reduce(
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
                  myResults.length
                ).toFixed(2)
              )
            : 0
      }
    });
  }
);

/* =========================================================
   SUPERADMIN - SCHOOLS
========================================================= */

app.get(
  "/api/admin/schools",
  requireRole("superadmin"),
  (req, res) => {
    res.json({
      ok: true,
      schools:
        getData("schools")
    });
  }
);

app.post(
  "/api/admin/schools",
  requireRole("superadmin"),
  (req, res) => {
    const schools =
      getData("schools");

    const {
      name,
      motto,
      primaryColor,
      secondaryColor,
      theme
    } = req.body;

    if (!clean(name)) {
      return res.status(400).json({
        ok: false,
        error:
          "School name is required."
      });
    }

    const school = {
      id:
        makeId("school"),

      name:
        clean(name),

      motto:
        clean(motto),

      logo: "",

      primaryColor:
        clean(
          primaryColor
        ) || "#2563eb",

      secondaryColor:
        clean(
          secondaryColor
        ) || "#16a34a",

      theme:
        clean(theme) ||
        "light",

      active:
        true,

      createdAt:
        now(),

      updatedAt:
        now()
    };

    schools.push(
      school
    );

    saveData(
      "schools",
      schools
    );

    res.status(201).json({
      ok: true,
      school
    });
  }
);

app.put(
  "/api/admin/schools/:id",
  requireRole("superadmin"),
  (req, res) => {
    const schools =
      getData("schools");

    const school =
      schools.find(
        (s) =>
          s.id ===
          req.params.id
      );

    if (!school) {
      return res.status(404).json({
        ok: false,
        error:
          "School not found."
      });
    }

    const fields = [
      "name",
      "motto",
      "primaryColor",
      "secondaryColor",
      "theme"
    ];

    fields.forEach(
      (field) => {
        if (
          req.body[field] !==
          undefined
        ) {
          school[field] =
            clean(
              req.body[field]
            );
        }
      }
    );

    if (
      req.body.active !==
      undefined
    ) {
      school.active =
        parseBoolean(
          req.body.active,
          true
        );
    }

    school.updatedAt =
      now();

    saveData(
      "schools",
      schools
    );

    res.json({
      ok: true,
      school
    });
  }
);

app.delete(
  "/api/admin/schools/:id",
  requireRole("superadmin"),
  (req, res) => {
    const schools =
      getData("schools");

    const school =
      schools.find(
        (s) =>
          s.id ===
          req.params.id
      );

    if (!school) {
      return res.status(404).json({
        ok: false,
        error:
          "School not found."
      });
    }

    /*
      Deactivate instead of
      permanently deleting school data.
    */

    school.active =
      false;

    school.updatedAt =
      now();

    saveData(
      "schools",
      schools
    );

    res.json({
      ok: true,
      message:
        "School deactivated.",
      school
    });
  }
);

/* =========================================================
   SUPERADMIN - ALL USERS
========================================================= */

app.get(
  "/api/admin/users",
  requireRole("superadmin"),
  (req, res) => {
    const users =
      getData("users");

    res.json({
      ok: true,
      users:
        users.map(
          (u) =>
            safeUser(u)
        )
    });
  }
);

app.put(
  "/api/admin/users/:id",
  requireRole("superadmin"),
  async (req, res) => {
    const users =
      getData("users");

    const user =
      users.find(
        (u) =>
          u.id ===
          req.params.id
      );

    if (!user) {
      return res.status(404).json({
        ok: false,
        error:
          "User not found."
      });
    }

    if (
      req.body.fullName !==
      undefined
    ) {
      user.fullName =
        clean(
          req.body.fullName
        );
    }

    if (
      req.body.username !==
      undefined
    ) {
      user.username =
        clean(
          req.body.username
        );
    }

    if (
      req.body.email !==
      undefined
    ) {
      user.email =
        lower(
          req.body.email
        );
    }

    if (
      req.body.role !==
      undefined
    ) {
      const validRoles = [
        "superadmin",
        "school_admin",
        "teacher",
        "student"
      ];

      if (
        validRoles.includes(
          req.body.role
        )
      ) {
        user.role =
          req.body.role;
      }
    }

    if (
      req.body.schoolId !==
      undefined
    ) {
      user.schoolId =
        clean(
          req.body.schoolId
        ) || null;
    }

    if (
      req.body.active !==
      undefined
    ) {
      user.active =
        parseBoolean(
          req.body.active,
          true
        );
    }

    if (
      req.body.password
    ) {
      user.passwordHash =
        await bcrypt.hash(
          req.body.password,
          12
        );
    }

    user.updatedAt =
      now();

    saveData(
      "users",
      users
    );

    res.json({
      ok: true,
      user:
        safeUser(user)
    });
  }
);

/* =========================================================
   PLATFORM SETTINGS
========================================================= */

app.get(
  "/api/admin/settings",
  requireRole("superadmin"),
  (req, res) => {
    res.json({
      ok: true,
      settings:
        getData("settings")
    });
  }
);

app.put(
  "/api/admin/settings",
  requireRole("superadmin"),
  (req, res) => {
    const settings =
      getData("settings");

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
        parseBoolean(
          req.body.maintenanceMode,
          false
        );
    }

    saveData(
      "settings",
      settings
    );

    res.json({
      ok: true,
      settings
    });
  }
);

/* =========================================================
   SUPERADMIN SUMMARY
========================================================= */

app.get(
  "/api/superadmin/summary",
  requireRole("superadmin"),
  (req, res) => {
    const users =
      getData("users");

    const schools =
      getData("schools");

    const subjects =
      getData("subjects");

    const exams =
      getData("exams");

    const questions =
      getData("questions");

    const results =
      getData("results");

    res.json({
      ok: true,

      summary: {
        schools:
          schools.length,

        activeSchools:
          schools.filter(
            (s) =>
              s.active !== false
          ).length,

        users:
          users.length,

        activeUsers:
          users.filter(
            (u) =>
              u.active !== false
          ).length,

        schoolAdmins:
          users.filter(
            (u) =>
              u.role ===
              "school_admin"
          ).length,

        teachers:
          users.filter(
            (u) =>
              u.role ===
              "teacher"
          ).length,

        students:
          users.filter(
            (u) =>
              u.role ===
              "student"
          ).length,

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

/* =========================================================
   DASHBOARD REDIRECT
========================================================= */

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

/* =========================================================
   STATIC FRONTEND
========================================================= */

app.use(
  express.static(
    PUBLIC_DIR,
    {
      extensions: [
        "html"
      ]
    }
  )
);

/* =========================================================
   ROOT
========================================================= */

app.get(
  "/",
  (req, res) => {
    const index =
      path.join(
        PUBLIC_DIR,
        "index.html"
      );

    if (fs.existsSync(index)) {
      return res.sendFile(
        index
      );
    }

    res.send(
      "SchoolHub Pro is running."
    );
  }
);

/* =========================================================
   API 404
========================================================= */

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      ok: false,
      error:
        "API route not found",
      method:
        req.method,
      path:
        req.originalUrl
    });
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {
    console.error(
      "SERVER ERROR:",
      error
    );

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

    if (
      error &&
      error.code ===
        "LIMIT_FILE_SIZE"
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "Image is too large. Maximum size is 5MB."
      });
    }

    res.status(500).json({
      ok: false,
      error:
        "Internal server error"
    });
  }
);

/* =========================================================
   SUPERADMIN CREATION
========================================================= */

async function ensureSuperadmin() {
  try {
    const email =
      lower(
        process.env.SUPERADMIN_EMAIL
      );

    const username =
      clean(
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

    if (
      !email ||
      !password
    ) {
      console.log(
        "Superadmin environment variables not configured."
      );

      return;
    }

    const users =
      getData("users");

    let user =
      users.find(
        (u) =>
          lower(u.email) ===
            email ||
          lower(u.username) ===
            lower(username)
      );

    if (user) {
      user.role =
        "superadmin";

      user.active =
        true;

      user.updatedAt =
        now();

      saveData(
        "users",
        users
      );

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
      id:
        makeId("user"),

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

    users.push(
      user
    );

    saveData(
      "users",
      users
    );

    console.log(
      `Superadmin created: ${email}`
    );
  } catch (error) {
    console.error(
      "SUPERADMIN SETUP ERROR:",
      error
    );
  }
}

/* =========================================================
   START SERVER
========================================================= */

let server;

async function startServer() {
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
          `Environment: ${NODE_ENV}`
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
          "Session Store: FILE"
        );
        console.log(
          "Question Bank: ENABLED"
        );
        console.log(
          "CBT System: ENABLED"
        );
        console.log(
          "School Branding: ENABLED"
        );
        console.log(
          "Profile Uploads: ENABLED"
        );
        console.log(
          "Multi-School Isolation: ENABLED"
        );
        console.log(
          "=========================================="
        );
        console.log("");
      }
    );
}

/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

function shutdown(signal) {
  console.log(
    `${signal} received. Shutting down...`
  );

  try {
    sessionStore.save();
  } catch {}

  if (!server) {
    process.exit(0);
    return;
  }

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
  ).unref();
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
  (error) => {
    console.error(
      "UNHANDLED REJECTION:",
      error
    );
  }
);

startServer();
