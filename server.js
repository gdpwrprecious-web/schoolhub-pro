/**
 * ============================================================
 * SCHOOLHUB PRO
 * MAIN SERVER
 * Multi-School School Management + CBT Platform
 * ============================================================
 *
 * Roles:
 *   superadmin
 *   school_admin
 *   teacher
 *   student
 *
 * Storage:
 *   JSON files
 *
 * Railway:
 *   STORAGE_ROOT=/app/storage
 *
 * Google OAuth:
 *   GOOGLE_CLIENT_ID
 *   GOOGLE_CLIENT_SECRET
 *   GOOGLE_CALLBACK_URL
 *
 * ============================================================
 */

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const dotenv = require("dotenv");
const path = require("path");
const fs = require("fs");

dotenv.config();

/* ============================================================
   APP CONFIG
============================================================ */

const app = express();

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";

const NODE_ENV = process.env.NODE_ENV || "development";

const PUBLIC_DIR = path.join(__dirname, "public");

const STORAGE_ROOT =
  process.env.STORAGE_ROOT ||
  path.join(__dirname, "data");

const DATA_DIR = path.join(STORAGE_ROOT, "data");

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "schoolhub-development-session-secret-change-this";

/* ============================================================
   CREATE DIRECTORIES
============================================================ */

function ensureDirectory(directory) {
  if (!fs.existsSync(directory)) {
    fs.mkdirSync(directory, {
      recursive: true
    });
  }
}

ensureDirectory(STORAGE_ROOT);
ensureDirectory(DATA_DIR);
ensureDirectory(PUBLIC_DIR);

/* ============================================================
   JSON DATABASE FILES
============================================================ */

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

/* ============================================================
   DEFAULT SETTINGS
============================================================ */

const DEFAULT_SETTINGS = {
  platformName: "SchoolHub Pro",
  platformDescription:
    "Smart school management and CBT platform for modern schools.",
  defaultTheme: "light",
  maintenanceMode: false,
  allowRegistration: true,
  allowGoogleLogin: true,
  version: "5.0.0"
};

/* ============================================================
   JSON HELPERS
============================================================ */

function ensureJsonFile(file, defaultValue) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(
      file,
      JSON.stringify(defaultValue, null, 2),
      "utf8"
    );
  }
}

function readJson(file, defaultValue) {
  try {
    ensureJsonFile(file, defaultValue);

    const raw = fs.readFileSync(file, "utf8").trim();

    if (!raw) {
      return defaultValue;
    }

    return JSON.parse(raw);
  } catch (error) {
    console.error("JSON READ ERROR:", file, error.message);

    try {
      fs.writeFileSync(
        file,
        JSON.stringify(defaultValue, null, 2),
        "utf8"
      );
    } catch (writeError) {
      console.error(
        "JSON RESET ERROR:",
        writeError.message
      );
    }

    return defaultValue;
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

/* ============================================================
   INITIALIZE DATABASE
============================================================ */

ensureJsonFile(FILES.users, []);
ensureJsonFile(FILES.schools, []);
ensureJsonFile(FILES.settings, DEFAULT_SETTINGS);
ensureJsonFile(FILES.subjects, []);
ensureJsonFile(FILES.exams, []);
ensureJsonFile(FILES.questions, []);
ensureJsonFile(FILES.results, []);
ensureJsonFile(FILES.announcements, []);

/* ============================================================
   ID / DATE HELPERS
============================================================ */

function id(prefix = "id") {
  return (
    prefix +
    "_" +
    Date.now().toString(36) +
    "_" +
    Math.random()
      .toString(36)
      .substring(2, 10)
  );
}

function now() {
  return new Date().toISOString();
}

function clean(value) {
  return String(value || "").trim();
}

function normalizeEmail(email) {
  return clean(email).toLowerCase();
}

function normalizeUsername(username) {
  return clean(username).toLowerCase();
}

/* ============================================================
   DATABASE GETTERS
============================================================ */

function getUsers() {
  return readJson(FILES.users, []);
}

function saveUsers(users) {
  writeJson(FILES.users, users);
}

function getSchools() {
  return readJson(FILES.schools, []);
}

function saveSchools(schools) {
  writeJson(FILES.schools, schools);
}

function getSettings() {
  return readJson(
    FILES.settings,
    DEFAULT_SETTINGS
  );
}

function saveSettings(settings) {
  writeJson(FILES.settings, settings);
}

function getSubjects() {
  return readJson(FILES.subjects, []);
}

function saveSubjects(items) {
  writeJson(FILES.subjects, items);
}

function getExams() {
  return readJson(FILES.exams, []);
}

function saveExams(items) {
  writeJson(FILES.exams, items);
}

function getQuestions() {
  return readJson(FILES.questions, []);
}

function saveQuestions(items) {
  writeJson(FILES.questions, items);
}

function getResults() {
  return readJson(FILES.results, []);
}

function saveResults(items) {
  writeJson(FILES.results, items);
}

function getAnnouncements() {
  return readJson(FILES.announcements, []);
}

function saveAnnouncements(items) {
  writeJson(FILES.announcements, items);
}

/* ============================================================
   EXPRESS MIDDLEWARE
============================================================ */

app.disable("x-powered-by");

app.use(
  express.json({
    limit: "10mb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "10mb"
  })
);

/* ============================================================
   SESSION
============================================================ */

app.use(
  session({
    secret: SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,

      secure:
        NODE_ENV === "production",

      sameSite: "lax",

      maxAge:
        7 * 24 * 60 * 60 * 1000
    }
  })
);

/* ============================================================
   PASSPORT
============================================================ */

app.use(passport.initialize());
app.use(passport.session());

/* ============================================================
   GOOGLE AUTH CONFIG
============================================================ */

const googleConfigured =
  Boolean(process.env.GOOGLE_CLIENT_ID) &&
  Boolean(process.env.GOOGLE_CLIENT_SECRET) &&
  Boolean(process.env.GOOGLE_CALLBACK_URL);

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
          let users = getUsers();

          const googleId = profile.id;

          const email = normalizeEmail(
            profile.emails &&
              profile.emails[0]
                ? profile.emails[0].value
                : ""
          );

          const profilePicture =
            profile.photos &&
            profile.photos[0]
              ? profile.photos[0].value
              : "";

          let user =
            users.find(
              (u) =>
                u.googleId === googleId
            ) ||
            users.find(
              (u) =>
                email &&
                normalizeEmail(u.email) ===
                  email
            );

          if (user) {
            user.googleId = googleId;

            if (
              !user.profilePicture &&
              profilePicture
            ) {
              user.profilePicture =
                profilePicture;
            }

            user.provider = "google";
            user.updatedAt = now();

            saveUsers(users);

            return done(null, user);
          }

          /*
           * Google accounts do not automatically
           * create a school account.
           *
           * The person should register first.
           */
          return done(
            null,
            false,
            {
              message:
                "No SchoolHub account was found for this Google account. Register first using the same email address."
            }
          );
        } catch (error) {
          console.error(
            "GOOGLE STRATEGY ERROR:",
            error
          );

          return done(error);
        }
      }
    )
  );
} else {
  console.log(
    "Google Auth: NOT CONFIGURED"
  );
}

passport.serializeUser(
  (user, done) => {
    done(null, user.id);
  }
);

passport.deserializeUser(
  (userId, done) => {
    try {
      const users = getUsers();

      const user = users.find(
        (u) => u.id === userId
      );

      if (!user) {
        return done(null, false);
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }
);

/* ============================================================
   USER SAFE RESPONSE
============================================================ */

function safeUser(user) {
  if (!user) {
    return null;
  }

  return {
    id: user.id,
    fullName: user.fullName,
    username: user.username,
    email: user.email,
    role: user.role,
    schoolId: user.schoolId || null,
    profilePicture:
      user.profilePicture || "",
    provider:
      user.provider || "local",
    active:
      user.active !== false,
    createdAt:
      user.createdAt || null
  };
}

/* ============================================================
   ROLE REDIRECT
============================================================ */

function roleRedirect(user) {
  if (!user) {
    return "/login.html";
  }

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

/* ============================================================
   AUTH MIDDLEWARE
============================================================ */

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      ok: false,
      message: "Authentication required."
    });
  }

  if (req.user.active === false) {
    return res.status(403).json({
      ok: false,
      message:
        "Your account has been deactivated."
    });
  }

  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        ok: false,
        message:
          "Authentication required."
      });
    }

    if (
      !roles.includes(req.user.role)
    ) {
      return res.status(403).json({
        ok: false,
        message:
          "You do not have permission to perform this action."
      });
    }

    next();
  };
}

function requireSuperadmin(
  req,
  res,
  next
) {
  if (!req.user) {
    return res.status(401).json({
      ok: false,
      message:
        "Authentication required."
    });
  }

  if (
    req.user.role !==
    "superadmin"
  ) {
    return res.status(403).json({
      ok: false,
      message:
        "Superadmin access required."
    });
  }

  next();
}

function requireSchoolAdmin(
  req,
  res,
  next
) {
  if (!req.user) {
    return res.status(401).json({
      ok: false,
      message:
        "Authentication required."
    });
  }

  if (
    ![
      "school_admin",
      "superadmin"
    ].includes(req.user.role)
  ) {
    return res.status(403).json({
      ok: false,
      message:
        "School administrator access required."
    });
  }

  next();
}

/* ============================================================
   SCHOOL ACCESS
============================================================ */

function getUserSchoolId(req) {
  if (!req.user) {
    return null;
  }

  return req.user.schoolId || null;
}

function schoolUserCanAccess(
  req,
  schoolId
) {
  if (
    req.user &&
    req.user.role === "superadmin"
  ) {
    return true;
  }

  return (
    req.user &&
    req.user.schoolId === schoolId
  );
}

/* ============================================================
   PLATFORM ROUTES
============================================================ */

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      ok: true,
      status: "online",
      service: "SchoolHub Pro",
      version: "5.0.0",
      environment: NODE_ENV,
      port: PORT,
      storage: STORAGE_ROOT,
      googleAuth:
        googleConfigured
          ? "CONFIGURED"
          : "NOT CONFIGURED",
      time: now()
    });
  }
);

app.get(
  "/api/platform",
  (req, res) => {
    const settings =
      getSettings();

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
          Boolean(
            settings.maintenanceMode
          ),

        allowRegistration:
          settings.allowRegistration !==
          false,

        allowGoogleLogin:
          googleConfigured &&
          settings.allowGoogleLogin !==
            false,

        version:
          settings.version ||
          "5.0.0"
      }
    });
  }
);

app.get(
  "/api/platform-config",
  (req, res) => {
    const settings =
      getSettings();

    res.json({
      ok: true,
      settings: {
        platformName:
          settings.platformName,

        platformDescription:
          settings.platformDescription,

        defaultTheme:
          settings.defaultTheme,

        maintenanceMode:
          Boolean(
            settings.maintenanceMode
          ),

        allowRegistration:
          settings.allowRegistration !==
          false,

        allowGoogleLogin:
          googleConfigured &&
          settings.allowGoogleLogin !==
            false
      }
    });
  }
);

/* ============================================================
   CURRENT USER
============================================================ */

app.get(
  "/api/me",
  (req, res) => {
    res.json({
      ok: true,
      authenticated:
        Boolean(req.user),

      user:
        req.user
          ? safeUser(req.user)
          : null,

      redirect:
        req.user
          ? roleRedirect(req.user)
          : "/login.html"
    });
  }
);

/* ============================================================
   REGISTER
============================================================ */

app.post(
  "/api/register",
  async (req, res) => {
    try {
      const settings =
        getSettings();

      if (
        settings.allowRegistration ===
        false
      ) {
        return res.status(403).json({
          ok: false,
          message:
            "Registration is currently disabled."
        });
      }

      const {
        schoolName,
        schoolMotto,
        fullName,
        username,
        email,
        password
      } = req.body;

      const cleanSchoolName =
        clean(schoolName);

      const cleanMotto =
        clean(schoolMotto);

      const cleanName =
        clean(fullName);

      const cleanUsername =
        normalizeUsername(
          username
        );

      const cleanEmail =
        normalizeEmail(email);

      if (
        !cleanSchoolName ||
        !cleanName ||
        !cleanUsername ||
        !cleanEmail ||
        !password
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Please complete all required fields."
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          ok: false,
          message:
            "Password must be at least 8 characters."
        });
      }

      const users =
        getUsers();

      const existingEmail =
        users.find(
          (u) =>
            normalizeEmail(
              u.email
            ) === cleanEmail
        );

      if (existingEmail) {
        return res.status(409).json({
          ok: false,
          message:
            "An account with this email already exists."
        });
      }

      const existingUsername =
        users.find(
          (u) =>
            normalizeUsername(
              u.username
            ) === cleanUsername
        );

      if (existingUsername) {
        return res.status(409).json({
          ok: false,
          message:
            "This username is already in use."
        });
      }

      const schools =
        getSchools();

      const schoolExists =
        schools.find(
          (school) =>
            school.name.toLowerCase() ===
            cleanSchoolName.toLowerCase()
        );

      if (schoolExists) {
        return res.status(409).json({
          ok: false,
          message:
            "A school with this name already exists."
        });
      }

      const schoolId =
        id("school");

      const userId =
        id("user");

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const school = {
        id: schoolId,

        name: cleanSchoolName,

        motto: cleanMotto,

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

      const user = {
        id: userId,

        fullName: cleanName,

        username:
          cleanUsername,

        email:
          cleanEmail,

        passwordHash,

        role:
          "school_admin",

        schoolId,

        profilePicture: "",

        provider: "local",

        active: true,

        createdAt: now(),

        updatedAt: now()
      };

      schools.push(school);

      users.push(user);

      saveSchools(schools);

      saveUsers(users);

      req.login(
        user,
        (loginError) => {
          if (loginError) {
            console.error(
              "REGISTER LOGIN ERROR:",
              loginError
            );

            return res.status(500).json({
              ok: false,
              message:
                "Account created, but automatic login failed. Please log in manually."
            });
          }

          return res.status(201).json({
            ok: true,

            message:
              "School account created successfully.",

            user:
              safeUser(user),

            redirect:
              "/admin.html"
          });
        }
      );
    } catch (error) {
      console.error(
        "REGISTER ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "An internal error occurred during registration."
      });
    }
  }
);

/* ============================================================
   LOGIN
============================================================ */

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const {
        identifier,
        email,
        username,
        password
      } = req.body;

      const loginIdentifier =
        clean(
          identifier ||
            email ||
            username
        ).toLowerCase();

      if (
        !loginIdentifier ||
        !password
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Enter your email/username and password."
        });
      }

      const users =
        getUsers();

      const user =
        users.find(
          (u) =>
            normalizeEmail(
              u.email
            ) === loginIdentifier ||
            normalizeUsername(
              u.username
            ) === loginIdentifier
        );

      if (!user) {
        return res.status(401).json({
          ok: false,
          message:
            "Invalid login details."
        });
      }

      if (
        user.active === false
      ) {
        return res.status(403).json({
          ok: false,
          message:
            "Your account has been deactivated."
        });
      }

      if (
        !user.passwordHash
      ) {
        return res.status(401).json({
          ok: false,
          message:
            "This account uses Google Sign-In. Use Google to sign in."
        });
      }

      const passwordValid =
        await bcrypt.compare(
          password,
          user.passwordHash
        );

      if (!passwordValid) {
        return res.status(401).json({
          ok: false,
          message:
            "Invalid login details."
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
              message:
                "An internal error occurred during login."
            });
          }

          return res.json({
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
    } catch (error) {
      console.error(
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "An internal error occurred during login."
      });
    }
  }
);

/* ============================================================
   LOGOUT
============================================================ */

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

          return res.status(500).json({
            ok: false,
            message:
              "Logout failed."
          });
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
              "connect.sid"
            );

            return res.json({
              ok: true,
              message:
                "Logged out successfully.",
              redirect:
                "/login.html"
            });
          }
        );
      }
    );
  }
);

/* ============================================================
   GOOGLE LOGIN
============================================================ */

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
        ]
      }
    )(req, res, next);
  }
);

/* ============================================================
   GOOGLE CALLBACK
============================================================ */

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
      (error, user, info) => {
        if (error) {
          console.error(
            "GOOGLE CALLBACK ERROR:",
            error
          );

          return res.redirect(
            "/login.html?error=google_auth_failed"
          );
        }

        if (!user) {
          const message =
            info &&
            info.message
              ? encodeURIComponent(
                  info.message
                )
              : "google_account_not_found";

          return res.redirect(
            `/login.html?error=${message}`
          );
        }

        if (
          user.active === false
        ) {
          return res.redirect(
            "/login.html?error=account_disabled"
          );
        }

        req.login(
          user,
          (loginError) => {
            if (loginError) {
              console.error(
                "GOOGLE SESSION ERROR:",
                loginError
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
    )(req, res, next);
  }
);

/* ============================================================
   SCHOOL
============================================================ */

app.get(
  "/api/school",
  requireAuth,
  (req, res) => {
    if (!req.user.schoolId) {
      return res.json({
        ok: true,
        school: null
      });
    }

    const schools =
      getSchools();

    const school =
      schools.find(
        (s) =>
          s.id ===
          req.user.schoolId
      );

    if (!school) {
      return res.status(404).json({
        ok: false,
        message:
          "School not found."
      });
    }

    res.json({
      ok: true,
      school
    });
  }
);

/* ============================================================
   SCHOOL BRANDING
============================================================ */

app.put(
  "/api/school/branding",
  requireRole(
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    const {
      name,
      motto,
      logo,
      primaryColor,
      secondaryColor,
      theme
    } = req.body;

    const targetSchoolId =
      req.user.role ===
      "superadmin"
        ? clean(
            req.body.schoolId
          )
        : req.user.schoolId;

    if (!targetSchoolId) {
      return res.status(400).json({
        ok: false,
        message:
          "School ID is required."
      });
    }

    const schools =
      getSchools();

    const school =
      schools.find(
        (s) =>
          s.id ===
          targetSchoolId
      );

    if (!school) {
      return res.status(404).json({
        ok: false,
        message:
          "School not found."
      });
    }

    if (
      req.user.role !==
        "superadmin" &&
      req.user.schoolId !==
        school.id
    ) {
      return res.status(403).json({
        ok: false,
        message:
          "You can only manage your own school's branding."
      });
    }

    if (
      name !== undefined &&
      clean(name)
    ) {
      school.name =
        clean(name);
    }

    if (
      motto !== undefined
    ) {
      school.motto =
        clean(motto);
    }

    if (
      logo !== undefined
    ) {
      school.logo =
        clean(logo);
    }

    if (
      primaryColor !==
        undefined &&
      clean(primaryColor)
    ) {
      school.primaryColor =
        clean(primaryColor);
    }

    if (
      secondaryColor !==
        undefined &&
      clean(secondaryColor)
    ) {
      school.secondaryColor =
        clean(
          secondaryColor
        );
    }

    if (
      theme !== undefined
    ) {
      school.theme =
        clean(theme) ||
        "light";
    }

    school.updatedAt =
      now();

    saveSchools(schools);

    res.json({
      ok: true,
      message:
        "School branding updated.",
      school
    });
  }
);

/* ============================================================
   USERS - SCHOOL ADMIN
============================================================ */

app.get(
  "/api/users",
  requireRole(
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    const users =
      getUsers();

    if (
      req.user.role ===
      "superadmin"
    ) {
      return res.json({
        ok: true,
        users: users.map(
          safeUser
        )
      });
    }

    const schoolUsers =
      users.filter(
        (u) =>
          u.schoolId ===
          req.user.schoolId
      );

    res.json({
      ok: true,
      users:
        schoolUsers.map(
          safeUser
        )
    });
  }
);

/* ============================================================
   CREATE SCHOOL USER
============================================================ */

app.post(
  "/api/users",
  requireRole(
    "school_admin",
    "superadmin"
  ),
  async (req, res) => {
    try {
      const {
        fullName,
        username,
        email,
        password,
        role,
        schoolId,
        profilePicture
      } = req.body;

      const cleanName =
        clean(fullName);

      const cleanUsername =
        normalizeUsername(
          username
        );

      const cleanEmail =
        normalizeEmail(email);

      if (
        !cleanName ||
        !cleanUsername ||
        !cleanEmail ||
        !password
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Full name, username, email and password are required."
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          ok: false,
          message:
            "Password must be at least 8 characters."
        });
      }

      const allowedRoles = [
        "school_admin",
        "teacher",
        "student"
      ];

      if (
        !allowedRoles.includes(
          role
        )
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Invalid user role."
        });
      }

      let targetSchoolId =
        req.user.schoolId;

      if (
        req.user.role ===
        "superadmin"
      ) {
        targetSchoolId =
          clean(schoolId);

        if (!targetSchoolId) {
          return res.status(400).json({
            ok: false,
            message:
              "School ID is required."
          });
        }
      }

      const schools =
        getSchools();

      const school =
        schools.find(
          (s) =>
            s.id ===
            targetSchoolId
        );

      if (!school) {
        return res.status(404).json({
          ok: false,
          message:
            "School not found."
        });
      }

      const users =
        getUsers();

      if (
        users.some(
          (u) =>
            normalizeEmail(
              u.email
            ) === cleanEmail
        )
      ) {
        return res.status(409).json({
          ok: false,
          message:
            "Email is already registered."
        });
      }

      if (
        users.some(
          (u) =>
            normalizeUsername(
              u.username
            ) ===
            cleanUsername
        )
      ) {
        return res.status(409).json({
          ok: false,
          message:
            "Username is already in use."
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const user = {
        id: id("user"),

        fullName:
          cleanName,

        username:
          cleanUsername,

        email:
          cleanEmail,

        passwordHash,

        role,

        schoolId:
          targetSchoolId,

        profilePicture:
          clean(
            profilePicture
          ),

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
        message:
          "Failed to create user."
      });
    }
  }
);

/* ============================================================
   UPDATE USER
============================================================ */

app.put(
  "/api/users/:id",
  requireRole(
    "school_admin",
    "superadmin"
  ),
  async (req, res) => {
    try {
      const users =
        getUsers();

      const user =
        users.find(
          (u) =>
            u.id ===
            req.params.id
        );

      if (!user) {
        return res.status(404).json({
          ok: false,
          message:
            "User not found."
        });
      }

      if (
        req.user.role !==
          "superadmin" &&
        user.schoolId !==
          req.user.schoolId
      ) {
        return res.status(403).json({
          ok: false,
          message:
            "You can only manage users in your school."
        });
      }

      const {
        fullName,
        username,
        email,
        password,
        role,
        active,
        profilePicture,
        schoolId
      } = req.body;

      if (
        fullName !== undefined
      ) {
        user.fullName =
          clean(fullName);
      }

      if (
        username !== undefined
      ) {
        const newUsername =
          normalizeUsername(
            username
          );

        const duplicate =
          users.find(
            (u) =>
              u.id !== user.id &&
              normalizeUsername(
                u.username
              ) ===
                newUsername
          );

        if (duplicate) {
          return res.status(409).json({
            ok: false,
            message:
              "Username already exists."
          });
        }

        user.username =
          newUsername;
      }

      if (
        email !== undefined
      ) {
        const newEmail =
          normalizeEmail(email);

        const duplicate =
          users.find(
            (u) =>
              u.id !== user.id &&
              normalizeEmail(
                u.email
              ) === newEmail
          );

        if (duplicate) {
          return res.status(409).json({
            ok: false,
            message:
              "Email already exists."
          });
        }

        user.email =
          newEmail;
      }

      if (
        password !== undefined &&
        clean(password)
      ) {
        if (
          password.length < 8
        ) {
          return res.status(400).json({
            ok: false,
            message:
              "Password must be at least 8 characters."
          });
        }

        user.passwordHash =
          await bcrypt.hash(
            password,
            12
          );
      }

      if (
        role !== undefined
      ) {
        if (
          req.user.role !==
            "superadmin" &&
          ![
            "teacher",
            "student",
            "school_admin"
          ].includes(role)
        ) {
          return res.status(400).json({
            ok: false,
            message:
              "Invalid role."
          });
        }

        if (
          req.user.role ===
            "superadmin" &&
          ![
            "superadmin",
            "school_admin",
            "teacher",
            "student"
          ].includes(role)
        ) {
          return res.status(400).json({
            ok: false,
            message:
              "Invalid role."
          });
        }

        user.role = role;
      }

      if (
        active !== undefined
      ) {
        user.active =
          Boolean(active);
      }

      if (
        profilePicture !==
        undefined
      ) {
        user.profilePicture =
          clean(
            profilePicture
          );
      }

      if (
        req.user.role ===
          "superadmin" &&
        schoolId !==
          undefined
      ) {
        const schools =
          getSchools();

        const school =
          schools.find(
            (s) =>
              s.id ===
              clean(schoolId)
          );

        if (!school) {
          return res.status(404).json({
            ok: false,
            message:
              "Target school not found."
          });
        }

        user.schoolId =
          clean(schoolId);
      }

      user.updatedAt =
        now();

      saveUsers(users);

      res.json({
        ok: true,
        message:
          "User updated successfully.",
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
        message:
          "Failed to update user."
      });
    }
  }
);

/* ============================================================
   DELETE USER
============================================================ */

app.delete(
  "/api/users/:id",
  requireRole(
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    const users =
      getUsers();

    const index =
      users.findIndex(
        (u) =>
          u.id ===
          req.params.id
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        message:
          "User not found."
      });
    }

    const user =
      users[index];

    if (
      req.user.id ===
      user.id
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "You cannot delete your own account."
      });
    }

    if (
      req.user.role !==
        "superadmin" &&
      user.schoolId !==
        req.user.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        message:
          "You cannot delete users from another school."
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

/* ============================================================
   PROFILE
============================================================ */

app.put(
  "/api/profile",
  requireAuth,
  async (req, res) => {
    try {
      const users =
        getUsers();

      const user =
        users.find(
          (u) =>
            u.id ===
            req.user.id
        );

      if (!user) {
        return res.status(404).json({
          ok: false,
          message:
            "User not found."
        });
      }

      const {
        fullName,
        profilePicture,
        password
      } = req.body;

      if (
        fullName !== undefined
      ) {
        user.fullName =
          clean(fullName);
      }

      if (
        profilePicture !==
        undefined
      ) {
        user.profilePicture =
          clean(
            profilePicture
          );
      }

      if (
        password !== undefined &&
        clean(password)
      ) {
        if (
          password.length < 8
        ) {
          return res.status(400).json({
            ok: false,
            message:
              "Password must be at least 8 characters."
          });
        }

        user.passwordHash =
          await bcrypt.hash(
            password,
            12
          );
      }

      user.updatedAt =
        now();

      saveUsers(users);

      req.user = user;

      res.json({
        ok: true,
        message:
          "Profile updated successfully.",
        user:
          safeUser(user)
      });
    } catch (error) {
      console.error(
        "PROFILE UPDATE ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Failed to update profile."
      });
    }
  }
);

/* ============================================================
   SUBJECTS
============================================================ */

app.get(
  "/api/subjects",
  requireAuth,
  (req, res) => {
    const subjects =
      getSubjects();

    if (
      req.user.role ===
      "superadmin"
    ) {
      return res.json({
        ok: true,
        subjects
      });
    }

    res.json({
      ok: true,

      subjects:
        subjects.filter(
          (subject) =>
            subject.schoolId ===
            req.user.schoolId
        )
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
    const {
      name,
      code,
      description,
      schoolId
    } = req.body;

    const cleanName =
      clean(name);

    if (!cleanName) {
      return res.status(400).json({
        ok: false,
        message:
          "Subject name is required."
      });
    }

    const targetSchoolId =
      req.user.role ===
      "superadmin"
        ? clean(schoolId)
        : req.user.schoolId;

    if (!targetSchoolId) {
      return res.status(400).json({
        ok: false,
        message:
          "School ID is required."
      });
    }

    const schools =
      getSchools();

    if (
      !schools.some(
        (s) =>
          s.id ===
          targetSchoolId
      )
    ) {
      return res.status(404).json({
        ok: false,
        message:
          "School not found."
      });
    }

    const subjects =
      getSubjects();

    const duplicate =
      subjects.find(
        (s) =>
          s.schoolId ===
            targetSchoolId &&
          s.name.toLowerCase() ===
            cleanName.toLowerCase()
      );

    if (duplicate) {
      return res.status(409).json({
        ok: false,
        message:
          "This subject already exists."
      });
    }

    const subject = {
      id: id("subject"),

      schoolId:
        targetSchoolId,

      name:
        cleanName,

      code:
        clean(code),

      description:
        clean(description),

      createdBy:
        req.user.id,

      createdAt: now(),

      updatedAt: now()
    };

    subjects.push(subject);

    saveSubjects(subjects);

    res.status(201).json({
      ok: true,
      message:
        "Subject created successfully.",
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
      getSubjects();

    const subject =
      subjects.find(
        (s) =>
          s.id ===
          req.params.id
      );

    if (!subject) {
      return res.status(404).json({
        ok: false,
        message:
          "Subject not found."
      });
    }

    if (
      req.user.role !==
        "superadmin" &&
      subject.schoolId !==
        req.user.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        message:
          "Access denied."
      });
    }

    const filtered =
      subjects.filter(
        (s) =>
          s.id !==
          req.params.id
      );

    saveSubjects(filtered);

    res.json({
      ok: true,
      message:
        "Subject deleted."
    });
  }
);

/* ============================================================
   EXAMS / CBT
============================================================ */

app.get(
  "/api/exams",
  requireAuth,
  (req, res) => {
    const exams =
      getExams();

    if (
      req.user.role ===
      "superadmin"
    ) {
      return res.json({
        ok: true,
        exams
      });
    }

    res.json({
      ok: true,

      exams:
        exams.filter(
          (exam) =>
            exam.schoolId ===
            req.user.schoolId
        )
    });
  }
);

app.post(
  "/api/exams",
  requireRole(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const {
      title,
      description,
      subjectId,
      duration,
      totalMarks,
      startTime,
      endTime,
      published,
      schoolId
    } = req.body;

    if (!clean(title)) {
      return res.status(400).json({
        ok: false,
        message:
          "Exam title is required."
      });
    }

    const targetSchoolId =
      req.user.role ===
      "superadmin"
        ? clean(schoolId)
        : req.user.schoolId;

    if (!targetSchoolId) {
      return res.status(400).json({
        ok: false,
        message:
          "School ID is required."
      });
    }

    const schools =
      getSchools();

    if (
      !schools.some(
        (s) =>
          s.id ===
          targetSchoolId
      )
    ) {
      return res.status(404).json({
        ok: false,
        message:
          "School not found."
      });
    }

    const exams =
      getExams();

    const exam = {
      id: id("exam"),

      schoolId:
        targetSchoolId,

      title:
        clean(title),

      description:
        clean(description),

      subjectId:
        clean(subjectId),

      duration:
        Number(duration) || 30,

      totalMarks:
        Number(totalMarks) || 0,

      startTime:
        startTime || null,

      endTime:
        endTime || null,

      published:
        Boolean(published),

      createdBy:
        req.user.id,

      createdAt: now(),

      updatedAt: now()
    };

    exams.push(exam);

    saveExams(exams);

    res.status(201).json({
      ok: true,
      message:
        "Exam created successfully.",
      exam
    });
  }
);

app.put(
  "/api/exams/:id",
  requireRole(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const exams =
      getExams();

    const exam =
      exams.find(
        (e) =>
          e.id ===
          req.params.id
      );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        message:
          "Exam not found."
      });
    }

    if (
      req.user.role !==
        "superadmin" &&
      exam.schoolId !==
        req.user.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        message:
          "Access denied."
      });
    }

    const allowedFields = [
      "title",
      "description",
      "subjectId",
      "duration",
      "totalMarks",
      "startTime",
      "endTime",
      "published"
    ];

    for (
      const field of allowedFields
    ) {
      if (
        req.body[field] !==
        undefined
      ) {
        exam[field] =
          req.body[field];
      }
    }

    exam.updatedAt =
      now();

    saveExams(exams);

    res.json({
      ok: true,
      message:
        "Exam updated successfully.",
      exam
    });
  }
);

/* ============================================================
   QUESTIONS
============================================================ */

app.get(
  "/api/questions",
  requireAuth,
  (req, res) => {
    const questions =
      getQuestions();

    let visible =
      questions;

    if (
      req.user.role !==
      "superadmin"
    ) {
      visible =
        questions.filter(
          (question) =>
            question.schoolId ===
            req.user.schoolId
        );
    }

    if (
      req.query.examId
    ) {
      visible =
        visible.filter(
          (question) =>
            question.examId ===
            req.query.examId
        );
    }

    if (
      req.query.subjectId
    ) {
      visible =
        visible.filter(
          (question) =>
            question.subjectId ===
            req.query.subjectId
        );
    }

    res.json({
      ok: true,
      questions: visible
    });
  }
);

app.post(
  "/api/questions",
  requireRole(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const {
      examId,
      subjectId,
      question,
      options,
      answer,
      points,
      difficulty,
      tags,
      schoolId
    } = req.body;

    if (
      !clean(question)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Question text is required."
      });
    }

    const targetSchoolId =
      req.user.role ===
      "superadmin"
        ? clean(schoolId)
        : req.user.schoolId;

    if (!targetSchoolId) {
      return res.status(400).json({
        ok: false,
        message:
          "School ID is required."
      });
    }

    const exams =
      getExams();

    if (examId) {
      const exam =
        exams.find(
          (e) =>
            e.id ===
            examId
        );

      if (!exam) {
        return res.status(404).json({
          ok: false,
          message:
            "Exam not found."
        });
      }

      if (
        exam.schoolId !==
        targetSchoolId
      ) {
        return res.status(403).json({
          ok: false,
          message:
            "Exam does not belong to this school."
        });
      }
    }

    const questions =
      getQuestions();

    const questionItem = {
      id: id("question"),

      schoolId:
        targetSchoolId,

      examId:
        clean(examId),

      subjectId:
        clean(subjectId),

      question:
        clean(question),

      options:
        Array.isArray(options)
          ? options
          : [],

      answer:
        Number.isFinite(
          Number(answer)
        )
          ? Number(answer)
          : 0,

      points:
        Number(points) || 1,

      difficulty:
        clean(
          difficulty
        ) || "medium",

      tags:
        clean(tags),

      createdBy:
        req.user.id,

      createdAt: now(),

      updatedAt: now()
    };

    questions.push(
      questionItem
    );

    saveQuestions(
      questions
    );

    res.status(201).json({
      ok: true,
      message:
        "Question created successfully.",
      question:
        questionItem
    });
  }
);

/* ============================================================
   START EXAM
============================================================ */

app.get(
  "/api/exams/:id/start",
  requireRole("student"),
  (req, res) => {
    const exams =
      getExams();

    const exam =
      exams.find(
        (e) =>
          e.id ===
          req.params.id
      );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        message:
          "Exam not found."
      });
    }

    if (
      exam.schoolId !==
      req.user.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        message:
          "This exam does not belong to your school."
      });
    }

    if (
      !exam.published
    ) {
      return res.status(403).json({
        ok: false,
        message:
          "This exam is not published."
      });
    }

    const questions =
      getQuestions()
        .filter(
          (q) =>
            q.examId ===
            exam.id
        )
        .map(
          (q) => ({
            id: q.id,

            question:
              q.question,

            options:
              q.options,

            points:
              q.points,

            difficulty:
              q.difficulty,

            tags:
              q.tags
          })
        );

    res.json({
      ok: true,

      exam,

      questions
    });
  }
);

/* ============================================================
   SUBMIT EXAM
============================================================ */

app.post(
  "/api/exams/:id/submit",
  requireRole("student"),
  (req, res) => {
    const exams =
      getExams();

    const exam =
      exams.find(
        (e) =>
          e.id ===
          req.params.id
      );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        message:
          "Exam not found."
      });
    }

    if (
      exam.schoolId !==
      req.user.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        message:
          "Access denied."
      });
    }

    const answers =
      req.body.answers || {};

    const questions =
      getQuestions().filter(
        (q) =>
          q.examId ===
          exam.id
      );

    let score = 0;

    let totalMarks = 0;

    const answerDetails =
      [];

    for (
      const question of questions
    ) {
      const points =
        Number(
          question.points
        ) || 1;

      totalMarks +=
        points;

      const submitted =
        answers[
          question.id
        ];

      const correct =
        Number(
          submitted
        ) ===
        Number(
          question.answer
        );

      if (correct) {
        score += points;
      }

      answerDetails.push({
        questionId:
          question.id,

        submittedAnswer:
          submitted !==
          undefined
            ? submitted
            : null,

        correct
      });
    }

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

    const results =
      getResults();

    const result = {
      id: id("result"),

      schoolId:
        req.user.schoolId,

      examId:
        exam.id,

      studentId:
        req.user.id,

      score,

      totalMarks,

      percentage,

      answers:
        answerDetails,

      submittedAt: now()
    };

    results.push(result);

    saveResults(results);

    res.json({
      ok: true,

      message:
        "Exam submitted successfully.",

      result
    });
  }
);

/* ============================================================
   RESULTS
============================================================ */

app.get(
  "/api/results",
  requireAuth,
  (req, res) => {
    const results =
      getResults();

    if (
      req.user.role ===
      "superadmin"
    ) {
      return res.json({
        ok: true,
        results
      });
    }

    if (
      req.user.role ===
      "student"
    ) {
      return res.json({
        ok: true,

        results:
          results.filter(
            (r) =>
              r.studentId ===
              req.user.id
          )
      });
    }

    res.json({
      ok: true,

      results:
        results.filter(
          (r) =>
            r.schoolId ===
            req.user.schoolId
        )
    });
  }
);

/* ============================================================
   ANNOUNCEMENTS
============================================================ */

app.get(
  "/api/announcements",
  requireAuth,
  (req, res) => {
    const announcements =
      getAnnouncements();

    if (
      req.user.role ===
      "superadmin"
    ) {
      return res.json({
        ok: true,
        announcements
      });
    }

    res.json({
      ok: true,

      announcements:
        announcements.filter(
          (a) =>
            a.schoolId ===
            req.user.schoolId
        )
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
    const {
      title,
      message,
      audience,
      schoolId
    } = req.body;

    if (
      !clean(title) ||
      !clean(message)
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Title and message are required."
      });
    }

    const targetSchoolId =
      req.user.role ===
      "superadmin"
        ? clean(schoolId)
        : req.user.schoolId;

    if (!targetSchoolId) {
      return res.status(400).json({
        ok: false,
        message:
          "School ID is required."
      });
    }

    const announcements =
      getAnnouncements();

    const announcement = {
      id:
        id("announcement"),

      schoolId:
        targetSchoolId,

      title:
        clean(title),

      message:
        clean(message),

      audience:
        clean(audience) ||
        "all",

      createdBy:
        req.user.id,

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

      message:
        "Announcement created successfully.",

      announcement
    });
  }
);

/* ============================================================
   SCHOOL ADMIN SUMMARY
============================================================ */

app.get(
  "/api/admin/summary",
  requireSchoolAdmin,
  (req, res) => {
    const schoolId =
      req.user.schoolId;

    const users =
      getUsers();

    const subjects =
      getSubjects();

    const exams =
      getExams();

    const questions =
      getQuestions();

    const results =
      getResults();

    const announcements =
      getAnnouncements();

    const schoolUsers =
      users.filter(
        (u) =>
          u.schoolId ===
          schoolId
      );

    const schoolExams =
      exams.filter(
        (e) =>
          e.schoolId ===
          schoolId
      );

    const schoolQuestions =
      questions.filter(
        (q) =>
          q.schoolId ===
          schoolId
      );

    const schoolResults =
      results.filter(
        (r) =>
          r.schoolId ===
          schoolId
      );

    res.json({
      ok: true,

      summary: {
        users:
          schoolUsers.length,

        teachers:
          schoolUsers.filter(
            (u) =>
              u.role ===
              "teacher"
          ).length,

        students:
          schoolUsers.filter(
            (u) =>
              u.role ===
              "student"
          ).length,

        schoolAdmins:
          schoolUsers.filter(
            (u) =>
              u.role ===
              "school_admin"
          ).length,

        subjects:
          subjects.filter(
            (s) =>
              s.schoolId ===
              schoolId
          ).length,

        exams:
          schoolExams.length,

        questions:
          schoolQuestions.length,

        results:
          schoolResults.length,

        announcements:
          announcements.filter(
            (a) =>
              a.schoolId ===
              schoolId
          ).length
      }
    });
  }
);

/* ============================================================
   TEACHER SUMMARY
============================================================ */

app.get(
  "/api/teacher/summary",
  requireRole("teacher"),
  (req, res) => {
    const schoolId =
      req.user.schoolId;

    const exams =
      getExams().filter(
        (e) =>
          e.schoolId ===
          schoolId
      );

    const subjects =
      getSubjects().filter(
        (s) =>
          s.schoolId ===
          schoolId
      );

    const questions =
      getQuestions().filter(
        (q) =>
          q.schoolId ===
          schoolId
      );

    const announcements =
      getAnnouncements().filter(
        (a) =>
          a.schoolId ===
          schoolId
      );

    res.json({
      ok: true,

      summary: {
        exams:
          exams.length,

        subjects:
          subjects.length,

        questions:
          questions.length,

        announcements:
          announcements.length
      }
    });
  }
);

/* ============================================================
   STUDENT SUMMARY
============================================================ */

app.get(
  "/api/student/summary",
  requireRole("student"),
  (req, res) => {
    const schoolId =
      req.user.schoolId;

    const exams =
      getExams().filter(
        (e) =>
          e.schoolId ===
            schoolId &&
          e.published
      );

    const results =
      getResults().filter(
        (r) =>
          r.studentId ===
          req.user.id
      );

    const announcements =
      getAnnouncements().filter(
        (a) =>
          a.schoolId ===
          schoolId
      );

    const subjects =
      getSubjects().filter(
        (s) =>
          s.schoolId ===
          schoolId
      );

    res.json({
      ok: true,

      summary: {
        availableExams:
          exams.length,

        completedExams:
          results.length,

        subjects:
          subjects.length,

        announcements:
          announcements.length
      }
    });
  }
);

/* ============================================================
   SUPERADMIN SUMMARY
============================================================ */

app.get(
  "/api/admin/summary",
  requireSuperadmin,
  (req, res) => {
    const users =
      getUsers();

    const schools =
      getSchools();

    const subjects =
      getSubjects();

    const exams =
      getExams();

    const questions =
      getQuestions();

    const results =
      getResults();

    const announcements =
      getAnnouncements();

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

        inactiveSchools:
          schools.filter(
            (s) =>
              s.active === false
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
          results.length,

        announcements:
          announcements.length
      }
    });
  }
);

/* ============================================================
   SUPERADMIN - ALL SCHOOLS
============================================================ */

app.get(
  "/api/admin/schools",
  requireSuperadmin,
  (req, res) => {
    const schools =
      getSchools();

    const users =
      getUsers();

    const exams =
      getExams();

    const subjects =
      getSubjects();

    const results =
      getResults();

    const output =
      schools.map(
        (school) => ({
          ...school,

          userCount:
            users.filter(
              (u) =>
                u.schoolId ===
                school.id
            ).length,

          teacherCount:
            users.filter(
              (u) =>
                u.schoolId ===
                  school.id &&
                u.role ===
                  "teacher"
            ).length,

          studentCount:
            users.filter(
              (u) =>
                u.schoolId ===
                  school.id &&
                u.role ===
                  "student"
            ).length,

          subjectCount:
            subjects.filter(
              (s) =>
                s.schoolId ===
                school.id
            ).length,

          examCount:
            exams.filter(
              (e) =>
                e.schoolId ===
                school.id
            ).length,

          resultCount:
            results.filter(
              (r) =>
                r.schoolId ===
                school.id
            ).length
        })
      );

    res.json({
      ok: true,
      schools: output
    });
  }
);

/* ============================================================
   SUPERADMIN - CREATE SCHOOL
============================================================ */

app.post(
  "/api/admin/schools",
  requireSuperadmin,
  (req, res) => {
    const {
      name,
      motto,
      logo,
      primaryColor,
      secondaryColor,
      theme
    } = req.body;

    const cleanName =
      clean(name);

    if (!cleanName) {
      return res.status(400).json({
        ok: false,
        message:
          "School name is required."
      });
    }

    const schools =
      getSchools();

    if (
      schools.some(
        (s) =>
          s.name.toLowerCase() ===
          cleanName.toLowerCase()
      )
    ) {
      return res.status(409).json({
        ok: false,
        message:
          "A school with this name already exists."
      });
    }

    const school = {
      id: id("school"),

      name:
        cleanName,

      motto:
        clean(motto),

      logo:
        clean(logo),

      primaryColor:
        clean(primaryColor) ||
        "#2563eb",

      secondaryColor:
        clean(
          secondaryColor
        ) ||
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

/* ============================================================
   SUPERADMIN - UPDATE SCHOOL
============================================================ */

app.put(
  "/api/admin/schools/:id",
  requireSuperadmin,
  (req, res) => {
    const schools =
      getSchools();

    const school =
      schools.find(
        (s) =>
          s.id ===
          req.params.id
      );

    if (!school) {
      return res.status(404).json({
        ok: false,
        message:
          "School not found."
      });
    }

    const {
      name,
      motto,
      logo,
      primaryColor,
      secondaryColor,
      theme,
      active
    } = req.body;

    if (
      name !== undefined
    ) {
      const newName =
        clean(name);

      if (!newName) {
        return res.status(400).json({
          ok: false,
          message:
            "School name cannot be empty."
        });
      }

      const duplicate =
        schools.find(
          (s) =>
            s.id !==
              school.id &&
            s.name.toLowerCase() ===
              newName.toLowerCase()
        );

      if (duplicate) {
        return res.status(409).json({
          ok: false,
          message:
            "Another school already has this name."
        });
      }

      school.name =
        newName;
    }

    if (
      motto !== undefined
    ) {
      school.motto =
        clean(motto);
    }

    if (
      logo !== undefined
    ) {
      school.logo =
        clean(logo);
    }

    if (
      primaryColor !==
      undefined
    ) {
      school.primaryColor =
        clean(
          primaryColor
        );
    }

    if (
      secondaryColor !==
      undefined
    ) {
      school.secondaryColor =
        clean(
          secondaryColor
        );
    }

    if (
      theme !== undefined
    ) {
      school.theme =
        clean(theme) ||
        "light";
    }

    if (
      active !== undefined
    ) {
      school.active =
        Boolean(active);
    }

    school.updatedAt =
      now();

    saveSchools(schools);

    /*
     * If a school is deactivated,
     * deactivate its users too.
     *
     * This preserves multi-school
     * security.
     */
    if (
      active !== undefined
    ) {
      const users =
        getUsers();

      let changed = false;

      users.forEach(
        (user) => {
          if (
            user.schoolId ===
            school.id
          ) {
            user.active =
              Boolean(active);

            user.updatedAt =
              now();

            changed = true;
          }
        }
      );

      if (changed) {
        saveUsers(users);
      }
    }

    res.json({
      ok: true,

      message:
        "School updated successfully.",

      school
    });
  }
);

/* ============================================================
   SUPERADMIN - ACTIVATE / DEACTIVATE SCHOOL
============================================================ */

app.put(
  "/api/admin/schools/:id/status",
  requireSuperadmin,
  (req, res) => {
    const {
      active
    } = req.body;

    const schools =
      getSchools();

    const school =
      schools.find(
        (s) =>
          s.id ===
          req.params.id
      );

    if (!school) {
      return res.status(404).json({
        ok: false,
        message:
          "School not found."
      });
    }

    school.active =
      Boolean(active);

    school.updatedAt =
      now();

    saveSchools(schools);

    const users =
      getUsers();

    users.forEach(
      (user) => {
        if (
          user.schoolId ===
          school.id
        ) {
          user.active =
            Boolean(active);

          user.updatedAt =
            now();
        }
      }
    );

    saveUsers(users);

    res.json({
      ok: true,

      message:
        school.active
          ? "School activated successfully."
          : "School deactivated successfully.",

      school
    });
  }
);

/* ============================================================
   SUPERADMIN - ALL USERS
============================================================ */

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
        (user) => {
          const school =
            schools.find(
              (s) =>
                s.id ===
                user.schoolId
            );

          return {
            ...safeUser(user),

            schoolName:
              school
                ? school.name
                : null
          };
        }
      );

    res.json({
      ok: true,
      users: output
    });
  }
);

/* ============================================================
   SUPERADMIN - PLATFORM SETTINGS
============================================================ */

app.put(
  "/api/admin/settings",
  requireSuperadmin,
  (req, res) => {
    const settings =
      getSettings();

    const allowedFields = [
      "platformName",
      "platformDescription",
      "defaultTheme",
      "maintenanceMode",
      "allowRegistration",
      "allowGoogleLogin"
    ];

    for (
      const field of allowedFields
    ) {
      if (
        req.body[field] !==
        undefined
      ) {
        settings[field] =
          req.body[field];
      }
    }

    settings.version =
      settings.version ||
      "5.0.0";

    saveSettings(settings);

    res.json({
      ok: true,

      message:
        "Platform settings updated.",

      settings
    });
  }
);

/* ============================================================
   SUPERADMIN - DELETE SCHOOL
============================================================ */

app.delete(
  "/api/admin/schools/:id",
  requireSuperadmin,
  (req, res) => {
    const schoolId =
      req.params.id;

    const schools =
      getSchools();

    const school =
      schools.find(
        (s) =>
          s.id ===
          schoolId
      );

    if (!school) {
      return res.status(404).json({
        ok: false,
        message:
          "School not found."
      });
    }

    /*
     * Safety rule:
     * delete school and all school-owned
     * data together.
     */

    saveSchools(
      schools.filter(
        (s) =>
          s.id !==
          schoolId
      )
    );

    saveUsers(
      getUsers().filter(
        (u) =>
          u.schoolId !==
          schoolId
      )
    );

    saveSubjects(
      getSubjects().filter(
        (s) =>
          s.schoolId !==
          schoolId
      )
    );

    saveExams(
      getExams().filter(
        (e) =>
          e.schoolId !==
          schoolId
      )
    );

    saveQuestions(
      getQuestions().filter(
        (q) =>
          q.schoolId !==
          schoolId
      )
    );

    saveResults(
      getResults().filter(
        (r) =>
          r.schoolId !==
          schoolId
      )
    );

    saveAnnouncements(
      getAnnouncements().filter(
        (a) =>
          a.schoolId !==
          schoolId
      )
    );

    res.json({
      ok: true,

      message:
        "School and its school data were deleted."
    });
  }
);

/* ============================================================
   SUPERADMIN USER STATUS
============================================================ */

app.put(
  "/api/admin/users/:id/status",
  requireSuperadmin,
  (req, res) => {
    const {
      active
    } = req.body;

    const users =
      getUsers();

    const user =
      users.find(
        (u) =>
          u.id ===
          req.params.id
      );

    if (!user) {
      return res.status(404).json({
        ok: false,
        message:
          "User not found."
      });
    }

    if (
      user.role ===
      "superadmin"
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Superadmin accounts cannot be disabled from this endpoint."
      });
    }

    user.active =
      Boolean(active);

    user.updatedAt =
      now();

    saveUsers(users);

    res.json({
      ok: true,

      message:
        user.active
          ? "User activated."
          : "User deactivated.",

      user:
        safeUser(user)
    });
  }
);

/* ============================================================
   DASHBOARD ROUTE
============================================================ */

app.get(
  "/dashboard",
  requireAuth,
  (req, res) => {
    res.redirect(
      roleRedirect(
        req.user
      )
    );
  }
);

/* ============================================================
   STATIC FILES
============================================================ */

app.use(
  express.static(
    PUBLIC_DIR,
    {
      index:
        "index.html"
    }
  )
);

/* ============================================================
   FRONTEND ROUTES
============================================================ */

app.get(
  "/",
  (req, res) => {
    res.sendFile(
      path.join(
        PUBLIC_DIR,
        "index.html"
      )
    );
  }
);

app.get(
  "/login",
  (req, res) => {
    res.sendFile(
      path.join(
        PUBLIC_DIR,
        "login.html"
      )
    );
  }
);

app.get(
  "/register",
  (req, res) => {
    res.sendFile(
      path.join(
        PUBLIC_DIR,
        "register.html"
      )
    );
  }
);

app.get(
  "/admin",
  (req, res) => {
    res.sendFile(
      path.join(
        PUBLIC_DIR,
        "admin.html"
      )
    );
  }
);

app.get(
  "/superadmin",
  (req, res) => {
    res.sendFile(
      path.join(
        PUBLIC_DIR,
        "superadmin.html"
      )
    );
  }
);

app.get(
  "/teacher",
  (req, res) => {
    res.sendFile(
      path.join(
        PUBLIC_DIR,
        "teacher.html"
      )
    );
  }
);

app.get(
  "/student",
  (req, res) => {
    res.sendFile(
      path.join(
        PUBLIC_DIR,
        "student.html"
      )
    );
  }
);

/* ============================================================
   API 404
============================================================ */

app.use(
  "/api",
  (req, res) => {
    res.status(404).json({
      ok: false,
      message:
        "API endpoint not found."
    });
  }
);

/* ============================================================
   FRONTEND FALLBACK
============================================================ */

app.use(
  (req, res) => {
    const requestedPath =
      req.path;

    if (
      requestedPath.includes(
        "."
      )
    ) {
      return res.status(404).send(
        "File not found."
      );
    }

    const indexPath =
      path.join(
        PUBLIC_DIR,
        "index.html"
      );

    if (
      fs.existsSync(indexPath)
    ) {
      return res.sendFile(
        indexPath
      );
    }

    res.status(404).send(
      "SchoolHub Pro"
    );
  }
);

/* ============================================================
   ERROR HANDLER
============================================================ */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "SERVER ERROR:",
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      ok: false,
      message:
        "Internal server error."
    });
  }
);

/* ============================================================
   ENSURE SUPERADMIN
============================================================ */

async function ensureSuperadmin() {
  try {
    const email =
      normalizeEmail(
        process.env.SUPERADMIN_EMAIL
      );

    const username =
      normalizeUsername(
        process.env.SUPERADMIN_USERNAME
      );

    const password =
      process.env.SUPERADMIN_PASSWORD;

    const fullName =
      clean(
        process.env.SUPERADMIN_NAME
      ) ||
      "SchoolHub Super Admin";

    if (
      !email ||
      !username ||
      !password
    ) {
      console.log(
        "Superadmin auto-setup: SKIPPED"
      );

      console.log(
        "Set SUPERADMIN_EMAIL, SUPERADMIN_USERNAME and SUPERADMIN_PASSWORD to create/promote a superadmin."
      );

      return;
    }

    if (password.length < 8) {
      console.error(
        "SUPERADMIN_PASSWORD must be at least 8 characters."
      );

      return;
    }

    const users =
      getUsers();

    let user =
      users.find(
        (u) =>
          normalizeEmail(
            u.email
          ) === email
      );

    if (!user) {
      user =
        users.find(
          (u) =>
            normalizeUsername(
              u.username
            ) === username
        );
    }

    if (user) {
      user.role =
        "superadmin";

      user.active =
        true;

      user.schoolId =
        null;

      user.updatedAt =
        now();

      /*
       * Only set missing identity data.
       * Existing password is not overwritten.
       */
      if (!user.fullName) {
        user.fullName =
          fullName;
      }

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

    const superadmin = {
      id: id("user"),

      fullName,

      username,

      email,

      passwordHash,

      role:
        "superadmin",

      schoolId: null,

      profilePicture: "",

      provider: "local",

      active: true,

      createdAt: now(),

      updatedAt: now()
    };

    users.push(
      superadmin
    );

    saveUsers(users);

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

/* ============================================================
   START SERVER
============================================================ */

let server;

async function startServer() {
  try {
    await ensureSuperadmin();

    server = app.listen(
      PORT,
      HOST,
      () => {
        console.log("");
        console.log(
          "=================================================="
        );
        console.log(
          " SCHOOLHUB PRO SERVER"
        );
        console.log(
          "=================================================="
        );
        console.log(
          ` Environment : ${NODE_ENV}`
        );
        console.log(
          ` Port        : ${PORT}`
        );
        console.log(
          ` Host        : ${HOST}`
        );
        console.log(
          ` Storage     : ${STORAGE_ROOT}`
        );
        console.log(
          ` Google Auth : ${
            googleConfigured
              ? "CONFIGURED"
              : "NOT CONFIGURED"
          }`
        );
        console.log(
          ` Public Dir  : ${PUBLIC_DIR}`
        );
        console.log(
          "=================================================="
        );
        console.log("");
      }
    );

    server.on(
      "error",
      (error) => {
        console.error(
          "SERVER LISTEN ERROR:",
          error
        );
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

/* ============================================================
   GRACEFUL SHUTDOWN
============================================================ */

function gracefulShutdown(
  signal
) {
  console.log(
    `${signal} received. Shutting down SchoolHub Pro...`
  );

  if (!server) {
    process.exit(0);
  }

  server.close(
    (error) => {
      if (error) {
        console.error(
          "SHUTDOWN ERROR:",
          error
        );

        process.exit(1);
      }

      console.log(
        "SchoolHub Pro stopped cleanly."
      );

      process.exit(0);
    }
  );
}

process.on(
  "SIGTERM",
  () =>
    gracefulShutdown(
      "SIGTERM"
    )
);

process.on(
  "SIGINT",
  () =>
    gracefulShutdown(
      "SIGINT"
    )
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

/* ============================================================
   START
============================================================ */

startServer();
