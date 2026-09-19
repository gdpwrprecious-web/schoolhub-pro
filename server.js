/**
 * ============================================================
 * SCHOOLHUB PRO
 * COMPLETE SCHOOL MANAGEMENT + CBT SERVER
 * ============================================================
 *
 * Features:
 * - Multi-school architecture
 * - Superadmin
 * - School Admin
 * - Teacher
 * - Student
 * - Google OAuth
 * - Normal login/register
 * - School branding
 * - User management
 * - Subjects
 * - CBT exams
 * - Question bank
 * - Results
 * - Announcements
 * - Dashboard APIs
 * - Railway persistent storage
 * - JSON database
 *
 * Google OAuth:
 * GOOGLE_CLIENT_ID
 * GOOGLE_CLIENT_SECRET
 * GOOGLE_CALLBACK_URL
 *
 * Railway:
 * STORAGE_ROOT=/app/storage
 *
 * ============================================================
 */

require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const fs = require("fs");
const path = require("path");

const app = express();

/* ============================================================
   CONFIG
============================================================ */

const PORT = Number(process.env.PORT || 3000);

const HOST = "0.0.0.0";

const NODE_ENV = process.env.NODE_ENV || "development";

const STORAGE_ROOT =
  process.env.STORAGE_ROOT ||
  path.join(__dirname, "storage");

const DATA_DIR = path.join(STORAGE_ROOT, "data");

const PUBLIC_DIR = path.join(__dirname, "public");

const USERS_FILE = path.join(DATA_DIR, "users.json");
const SCHOOLS_FILE = path.join(DATA_DIR, "schools.json");
const SUBJECTS_FILE = path.join(DATA_DIR, "subjects.json");
const EXAMS_FILE = path.join(DATA_DIR, "exams.json");
const QUESTIONS_FILE = path.join(DATA_DIR, "questions.json");
const RESULTS_FILE = path.join(DATA_DIR, "results.json");
const ANNOUNCEMENTS_FILE = path.join(DATA_DIR, "announcements.json");
const SETTINGS_FILE = path.join(DATA_DIR, "settings.json");

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "schoolhub-development-secret-change-this";

/* ============================================================
   CREATE DIRECTORIES
============================================================ */

function ensureDir(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

ensureDir(STORAGE_ROOT);
ensureDir(DATA_DIR);
ensureDir(PUBLIC_DIR);

/* ============================================================
   JSON DATABASE HELPERS
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

ensureJsonFile(USERS_FILE, []);
ensureJsonFile(SCHOOLS_FILE, []);
ensureJsonFile(SUBJECTS_FILE, []);
ensureJsonFile(EXAMS_FILE, []);
ensureJsonFile(QUESTIONS_FILE, []);
ensureJsonFile(RESULTS_FILE, []);
ensureJsonFile(ANNOUNCEMENTS_FILE, []);

ensureJsonFile(SETTINGS_FILE, {
  platformName: "SchoolHub Pro",
  platformDescription:
    "Smart school management and CBT platform.",
  defaultTheme: "light",
  maintenanceMode: false
});

function readJson(file, fallback = []) {
  try {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(
        file,
        JSON.stringify(fallback, null, 2),
        "utf8"
      );
      return fallback;
    }

    const content = fs.readFileSync(file, "utf8").trim();

    if (!content) {
      return fallback;
    }

    return JSON.parse(content);
  } catch (error) {
    console.error("JSON READ ERROR:", file, error.message);
    return fallback;
  }
}

function writeJson(file, data) {
  const temp = `${file}.tmp`;

  fs.writeFileSync(
    temp,
    JSON.stringify(data, null, 2),
    "utf8"
  );

  fs.renameSync(temp, file);
}

function users() {
  return readJson(USERS_FILE, []);
}

function schools() {
  return readJson(SCHOOLS_FILE, []);
}

function subjects() {
  return readJson(SUBJECTS_FILE, []);
}

function exams() {
  return readJson(EXAMS_FILE, []);
}

function questions() {
  return readJson(QUESTIONS_FILE, []);
}

function results() {
  return readJson(RESULTS_FILE, []);
}

function announcements() {
  return readJson(ANNOUNCEMENTS_FILE, []);
}

function settings() {
  return readJson(SETTINGS_FILE, {
    platformName: "SchoolHub Pro",
    platformDescription:
      "Smart school management and CBT platform.",
    defaultTheme: "light",
    maintenanceMode: false
  });
}

/* ============================================================
   ID GENERATOR
============================================================ */

function id(prefix = "id") {
  return `${prefix}_${Date.now()}_${Math.random()
    .toString(36)
    .substring(2, 10)}`;
}

/* ============================================================
   BASIC HELPERS
============================================================ */

function clean(value) {
  return String(value || "").trim();
}

function lower(value) {
  return clean(value).toLowerCase();
}

function now() {
  return new Date().toISOString();
}

function publicUser(user) {
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
    createdAt: user.createdAt
  };
}

function findUserById(userId) {
  return users().find(u => u.id === userId);
}

function findSchoolById(schoolId) {
  return schools().find(s => s.id === schoolId);
}

function roleRedirect(user) {
  if (!user) return "/login.html";

  if (
    user.role === "superadmin" ||
    user.role === "school_admin"
  ) {
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
   EXPRESS
============================================================ */

app.disable("x-powered-by");

app.set("trust proxy", 1);

app.use(express.json({ limit: "10mb" }));

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

      secure: NODE_ENV === "production",

      sameSite: "lax",

      maxAge: 7 * 24 * 60 * 60 * 1000
    }
  })
);

/* ============================================================
   PASSPORT
============================================================ */

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((userId, done) => {
  const user = findUserById(userId);

  if (!user) {
    return done(null, false);
  }

  done(null, user);
});

/* ============================================================
   GOOGLE AUTH CONFIGURATION
============================================================ */

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
          const allUsers = users();

          const googleId = profile.id;

          const email =
            lower(
              profile.emails &&
              profile.emails[0]
                ? profile.emails[0].value
                : ""
            );

          const fullName =
            profile.displayName ||
            "Google User";

          const picture =
            profile.photos &&
            profile.photos[0]
              ? profile.photos[0].value
              : "";

          if (!email) {
            return done(
              new Error(
                "Google account did not provide an email address."
              )
            );
          }

          let user =
            allUsers.find(
              u => u.googleId === googleId
            ) ||
            allUsers.find(
              u =>
                lower(u.email) === email
            );

          /*
           * IMPORTANT:
           * Google does not automatically create a
           * SchoolHub account.
           *
           * User must register first with the same email,
           * then Google can connect to that account.
           */

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

          user.profilePicture =
            picture ||
            user.profilePicture ||
            "";

          user.updatedAt = now();

          writeJson(USERS_FILE, allUsers);

          done(null, user);
        } catch (error) {
          done(error);
        }
      }
    )
  );

  console.log("Google Auth: CONFIGURED");
} else {
  console.log("Google Auth: NOT CONFIGURED");
}

/* ============================================================
   AUTH MIDDLEWARE
============================================================ */

function requireAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }

  if (req.session && req.session.userId) {
    const user = findUserById(
      req.session.userId
    );

    if (user) {
      req.user = user;
      return next();
    }
  }

  return res.status(401).json({
    ok: false,
    message: "Authentication required."
  });
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        ok: false,
        message: "Authentication required."
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        ok: false,
        message: "You do not have permission."
      });
    }

    next();
  };
}

function requireSchoolAdmin(req, res, next) {
  if (
    !req.user ||
    ![
      "school_admin",
      "superadmin"
    ].includes(req.user.role)
  ) {
    return res.status(403).json({
      ok: false,
      message: "School administrator access required."
    });
  }

  next();
}

function sameSchool(req, schoolId) {
  if (!req.user) return false;

  if (req.user.role === "superadmin") {
    return true;
  }

  return req.user.schoolId === schoolId;
}

/* ============================================================
   REQUEST USER
============================================================ */

app.use((req, res, next) => {
  if (!req.user && req.session.userId) {
    req.user = findUserById(
      req.session.userId
    );
  }

  next();
});

/* ============================================================
   HEALTH
============================================================ */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    status: "online",
    service: "SchoolHub Pro",
    version: "5.0.0",
    environment: NODE_ENV,
    port: PORT,
    storage: STORAGE_ROOT,
    googleAuth: googleConfigured
      ? "CONFIGURED"
      : "NOT CONFIGURED",
    time: now()
  });
});

/* ============================================================
   PLATFORM
============================================================ */

app.get("/api/platform", (req, res) => {
  res.json({
    ok: true,
    platform: settings()
  });
});

app.get(
  "/api/platform-config",
  (req, res) => {
    const config = settings();

    res.json({
      ok: true,

      platformName:
        config.platformName ||
        "SchoolHub Pro",

      platformDescription:
        config.platformDescription ||
        "",

      defaultTheme:
        config.defaultTheme ||
        "light",

      googleAuth:
        googleConfigured,

      maintenanceMode:
        Boolean(config.maintenanceMode)
    });
  }
);

/* ============================================================
   CURRENT USER
============================================================ */

app.get(
  "/api/me",
  requireAuth,
  (req, res) => {
    const school =
      req.user.schoolId
        ? findSchoolById(
            req.user.schoolId
          )
        : null;

    res.json({
      ok: true,

      user: publicUser(req.user),

      school: school || null,

      redirect:
        roleRedirect(req.user)
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
      const {
        schoolName,
        schoolMotto,
        fullName,
        username,
        email,
        password
      } = req.body;

      const schoolNameClean =
        clean(schoolName);

      const nameClean =
        clean(fullName);

      const usernameClean =
        lower(username);

      const emailClean =
        lower(email);

      if (
        !schoolNameClean ||
        !nameClean ||
        !usernameClean ||
        !emailClean ||
        !password
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Please complete all required fields."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          ok: false,
          message:
            "Password must be at least 6 characters."
        });
      }

      const allUsers = users();

      if (
        allUsers.some(
          u =>
            lower(u.email) ===
            emailClean
        )
      ) {
        return res.status(409).json({
          ok: false,
          message:
            "An account with this email already exists."
        });
      }

      if (
        allUsers.some(
          u =>
            lower(u.username) ===
            usernameClean
        )
      ) {
        return res.status(409).json({
          ok: false,
          message:
            "Username already exists."
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

        name: schoolNameClean,

        motto:
          clean(schoolMotto) ||
          "Smart education for a brighter future.",

        logo: "",

        primaryColor: "#2563eb",

        secondaryColor: "#16a34a",

        theme: "light",

        active: true,

        createdAt: now(),

        updatedAt: now()
      };

      const user = {
        id: userId,

        fullName: nameClean,

        username: usernameClean,

        email: emailClean,

        passwordHash,

        role: "school_admin",

        schoolId,

        profilePicture: "",

        provider: "local",

        active: true,

        createdAt: now(),

        updatedAt: now()
      };

      const allSchools =
        schools();

      allSchools.push(school);

      allUsers.push(user);

      writeJson(
        SCHOOLS_FILE,
        allSchools
      );

      writeJson(
        USERS_FILE,
        allUsers
      );

      req.session.userId =
        user.id;

      req.login(user, err => {
        if (err) {
          console.error(
            "REGISTER LOGIN ERROR:",
            err
          );
        }
      });

      res.status(201).json({
        ok: true,

        message:
          "School account created successfully.",

        user: publicUser(user),

        school,

        redirect: "/admin.html"
      });
    } catch (error) {
      console.error(
        "REGISTER ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to create account."
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
      const login =
        lower(
          req.body.login ||
          req.body.email ||
          req.body.username
        );

      const password =
        String(
          req.body.password || ""
        );

      if (!login || !password) {
        return res.status(400).json({
          ok: false,
          message:
            "Enter your username/email and password."
        });
      }

      const allUsers =
        users();

      const user =
        allUsers.find(
          u =>
            lower(u.email) ===
              login ||
            lower(u.username) ===
              login
        );

      if (!user) {
        return res.status(401).json({
          ok: false,
          message:
            "Invalid login details."
        });
      }

      if (user.active === false) {
        return res.status(403).json({
          ok: false,
          message:
            "This account has been disabled."
        });
      }

      if (!user.passwordHash) {
        return res.status(401).json({
          ok: false,
          message:
            "This account uses Google Sign-In. Please use Google."
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          user.passwordHash
        );

      if (!valid) {
        return res.status(401).json({
          ok: false,
          message:
            "Invalid login details."
        });
      }

      req.session.userId =
        user.id;

      req.login(user, err => {
        if (err) {
          console.error(
            "PASSPORT LOGIN ERROR:",
            err
          );

          return res.status(500).json({
            ok: false,
            message:
              "Login session could not be created."
          });
        }

        return res.json({
          ok: true,

          message:
            "Login successful.",

          user: publicUser(user),

          redirect:
            roleRedirect(user)
        });
      });
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
    req.logout(err => {
      if (err) {
        console.error(
          "LOGOUT ERROR:",
          err
        );
      }

      req.session.destroy(() => {
        res.clearCookie("connect.sid");

        res.json({
          ok: true,
          message:
            "Logged out successfully."
        });
      });
    });
  }
);

/* ============================================================
   GOOGLE AUTH
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
          "/login.html?error=google_failed",

        failureMessage: true
      },
      (err, user) => {
        if (err) {
          console.error(
            "GOOGLE CALLBACK ERROR:",
            err.message
          );

          return res.redirect(
            "/login.html?error=" +
              encodeURIComponent(
                err.message
              )
          );
        }

        if (!user) {
          return res.redirect(
            "/login.html?error=google_failed"
          );
        }

        req.logIn(
          user,
          loginError => {
            if (loginError) {
              console.error(
                "GOOGLE SESSION ERROR:",
                loginError
              );

              return res.redirect(
                "/login.html?error=session_failed"
              );
            }

            req.session.userId =
              user.id;

            req.session.save(
              saveError => {
                if (saveError) {
                  console.error(
                    "SESSION SAVE ERROR:",
                    saveError
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

/* ============================================================
   SCHOOL INFORMATION
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

    const school =
      findSchoolById(
        req.user.schoolId
      );

    res.json({
      ok: true,
      school: school || null
    });
  }
);

/* ============================================================
   SCHOOL BRANDING
============================================================ */

app.put(
  "/api/school/branding",
  requireAuth,
  requireSchoolAdmin,
  (req, res) => {
    if (
      req.user.role !==
      "superadmin" &&
      !req.user.schoolId
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "No school is associated with this account."
      });
    }

    const schoolId =
      req.user.role === "superadmin"
        ? clean(req.body.schoolId)
        : req.user.schoolId;

    const allSchools =
      schools();

    const school =
      allSchools.find(
        s => s.id === schoolId
      );

    if (!school) {
      return res.status(404).json({
        ok: false,
        message:
          "School not found."
      });
    }

    if (
      req.user.role !== "superadmin" &&
      school.id !== req.user.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        message:
          "You cannot edit another school."
      });
    }

    if (
      req.body.name !== undefined
    ) {
      school.name =
        clean(req.body.name);
    }

    if (
      req.body.motto !== undefined
    ) {
      school.motto =
        clean(req.body.motto);
    }

    if (
      req.body.logo !== undefined
    ) {
      school.logo =
        clean(req.body.logo);
    }

    if (
      req.body.primaryColor !== undefined
    ) {
      school.primaryColor =
        clean(req.body.primaryColor);
    }

    if (
      req.body.secondaryColor !== undefined
    ) {
      school.secondaryColor =
        clean(req.body.secondaryColor);
    }

    if (
      req.body.theme !== undefined
    ) {
      const allowedThemes = [
        "light",
        "dark",
        "blue",
        "green"
      ];

      if (
        allowedThemes.includes(
          req.body.theme
        )
      ) {
        school.theme =
          req.body.theme;
      }
    }

    school.updatedAt = now();

    writeJson(
      SCHOOLS_FILE,
      allSchools
    );

    res.json({
      ok: true,
      message:
        "School branding updated.",
      school
    });
  }
);

/* ============================================================
   USER MANAGEMENT
============================================================ */

app.get(
  "/api/users",
  requireAuth,
  requireSchoolAdmin,
  (req, res) => {
    const allUsers =
      users();

    let visible;

    if (
      req.user.role ===
      "superadmin"
    ) {
      visible = allUsers;
    } else {
      visible =
        allUsers.filter(
          u =>
            u.schoolId ===
            req.user.schoolId
        );
    }

    res.json({
      ok: true,

      users:
        visible.map(publicUser)
    });
  }
);

/* ============================================================
   CREATE USER
============================================================ */

app.post(
  "/api/users",
  requireAuth,
  requireSchoolAdmin,
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

      const allowedRoles = [
        "teacher",
        "student"
      ];

      if (
        !allowedRoles.includes(role)
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "School admins can create teachers and students."
        });
      }

      const nameClean =
        clean(fullName);

      const usernameClean =
        lower(username);

      const emailClean =
        lower(email);

      const targetSchoolId =
        req.user.role ===
        "superadmin"
          ? clean(schoolId)
          : req.user.schoolId;

      if (
        !nameClean ||
        !usernameClean ||
        !emailClean ||
        !password ||
        !targetSchoolId
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Complete all required fields."
        });
      }

      const school =
        findSchoolById(
          targetSchoolId
        );

      if (!school) {
        return res.status(404).json({
          ok: false,
          message:
            "School not found."
        });
      }

      const allUsers =
        users();

      if (
        allUsers.some(
          u =>
            lower(u.email) ===
            emailClean
        )
      ) {
        return res.status(409).json({
          ok: false,
          message:
            "Email already exists."
        });
      }

      if (
        allUsers.some(
          u =>
            lower(u.username) ===
            usernameClean
        )
      ) {
        return res.status(409).json({
          ok: false,
          message:
            "Username already exists."
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const user = {
        id: id("user"),

        fullName: nameClean,

        username: usernameClean,

        email: emailClean,

        passwordHash,

        role,

        schoolId:
          targetSchoolId,

        profilePicture:
          clean(profilePicture),

        provider: "local",

        active: true,

        createdAt: now(),

        updatedAt: now()
      };

      allUsers.push(user);

      writeJson(
        USERS_FILE,
        allUsers
      );

      res.status(201).json({
        ok: true,

        message:
          `${role} created successfully.`,

        user:
          publicUser(user)
      });
    } catch (error) {
      console.error(
        "CREATE USER ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Could not create user."
      });
    }
  }
);

/* ============================================================
   UPDATE USER
============================================================ */

app.put(
  "/api/users/:id",
  requireAuth,
  requireSchoolAdmin,
  async (req, res) => {
    try {
      const allUsers =
        users();

      const user =
        allUsers.find(
          u =>
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
            "You cannot manage this user."
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
        req.body.email !==
        undefined
      ) {
        user.email =
          lower(
            req.body.email
          );
      }

      if (
        req.body.username !==
        undefined
      ) {
        user.username =
          lower(
            req.body.username
          );
      }

      if (
        req.body.role !==
        undefined
      ) {
        if (
          req.user.role ===
            "superadmin" ||
          [
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
          Boolean(
            req.body.active
          );
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
        req.body.password
      ) {
        user.passwordHash =
          await bcrypt.hash(
            req.body.password,
            12
          );
      }

      user.updatedAt = now();

      writeJson(
        USERS_FILE,
        allUsers
      );

      res.json({
        ok: true,
        message:
          "User updated.",
        user:
          publicUser(user)
      });
    } catch (error) {
      console.error(
        "UPDATE USER ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Could not update user."
      });
    }
  }
);

/* ============================================================
   DELETE / DEACTIVATE USER
============================================================ */

app.delete(
  "/api/users/:id",
  requireAuth,
  requireSchoolAdmin,
  (req, res) => {
    const allUsers =
      users();

    const user =
      allUsers.find(
        u =>
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
          "You cannot manage this user."
      });
    }

    user.active = false;

    user.updatedAt = now();

    writeJson(
      USERS_FILE,
      allUsers
    );

    res.json({
      ok: true,
      message:
        "User deactivated."
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
      const allUsers =
        users();

      const user =
        allUsers.find(
          u =>
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
        req.body.profilePicture !==
        undefined
      ) {
        user.profilePicture =
          clean(
            req.body.profilePicture
          );
      }

      if (
        req.body.password
      ) {
        if (
          req.body.password.length <
          6
        ) {
          return res.status(400).json({
            ok: false,
            message:
              "Password must be at least 6 characters."
          });
        }

        user.passwordHash =
          await bcrypt.hash(
            req.body.password,
            12
          );
      }

      user.updatedAt = now();

      writeJson(
        USERS_FILE,
        allUsers
      );

      req.user = user;

      res.json({
        ok: true,

        message:
          "Profile updated.",

        user:
          publicUser(user)
      });
    } catch (error) {
      console.error(
        "PROFILE ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Could not update profile."
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
    let data =
      subjects();

    if (
      req.user.role !==
      "superadmin"
    ) {
      data =
        data.filter(
          s =>
            s.schoolId ===
            req.user.schoolId
        );
    }

    res.json({
      ok: true,
      subjects: data
    });
  }
);

/* ============================================================
   CREATE SUBJECT
============================================================ */

app.post(
  "/api/subjects",
  requireAuth,
  requireSchoolAdmin,
  (req, res) => {
    const name =
      clean(req.body.name);

    const code =
      clean(req.body.code);

    const description =
      clean(req.body.description);

    const schoolId =
      req.user.role ===
      "superadmin"
        ? clean(req.body.schoolId)
        : req.user.schoolId;

    if (!name || !schoolId) {
      return res.status(400).json({
        ok: false,
        message:
          "Subject name and school are required."
      });
    }

    const school =
      findSchoolById(
        schoolId
      );

    if (!school) {
      return res.status(404).json({
        ok: false,
        message:
          "School not found."
      });
    }

    const allSubjects =
      subjects();

    const subject = {
      id: id("subject"),

      schoolId,

      name,

      code,

      description,

      active: true,

      createdAt: now(),

      updatedAt: now()
    };

    allSubjects.push(subject);

    writeJson(
      SUBJECTS_FILE,
      allSubjects
    );

    res.status(201).json({
      ok: true,
      message:
        "Subject created.",
      subject
    });
  }
);

/* ============================================================
   DELETE SUBJECT
============================================================ */

app.delete(
  "/api/subjects/:id",
  requireAuth,
  requireSchoolAdmin,
  (req, res) => {
    const allSubjects =
      subjects();

    const subject =
      allSubjects.find(
        s =>
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

    subject.active = false;

    subject.updatedAt = now();

    writeJson(
      SUBJECTS_FILE,
      allSubjects
    );

    res.json({
      ok: true,
      message:
        "Subject disabled."
    });
  }
);

/* ============================================================
   EXAMS
============================================================ */

app.get(
  "/api/exams",
  requireAuth,
  (req, res) => {
    let data =
      exams();

    if (
      req.user.role !==
      "superadmin"
    ) {
      data =
        data.filter(
          exam =>
            exam.schoolId ===
            req.user.schoolId
        );
    }

    /*
     * Students should not receive
     * answer keys.
     */

    if (
      req.user.role ===
      "student"
    ) {
      data =
        data.map(exam => ({
          ...exam,
          questions:
            undefined
        }));
    }

    res.json({
      ok: true,
      exams: data
    });
  }
);

/* ============================================================
   CREATE EXAM
============================================================ */

app.post(
  "/api/exams",
  requireAuth,
  requireSchoolAdmin,
  (req, res) => {
    const title =
      clean(req.body.title);

    const subjectId =
      clean(req.body.subjectId);

    const duration =
      Number(
        req.body.duration || 30
      );

    const instructions =
      clean(
        req.body.instructions
      );

    const schoolId =
      req.user.role ===
      "superadmin"
        ? clean(req.body.schoolId)
        : req.user.schoolId;

    if (
      !title ||
      !subjectId ||
      !schoolId
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Exam title, subject and school are required."
      });
    }

    const allExams =
      exams();

    const exam = {
      id: id("exam"),

      schoolId,

      subjectId,

      title,

      instructions,

      duration:
        Number.isFinite(duration) &&
        duration > 0
          ? duration
          : 30,

      status:
        req.body.status ===
        "published"
          ? "published"
          : "draft",

      questions: [],

      createdBy:
        req.user.id,

      createdAt: now(),

      updatedAt: now()
    };

    allExams.push(exam);

    writeJson(
      EXAMS_FILE,
      allExams
    );

    res.status(201).json({
      ok: true,
      message:
        "Exam created.",
      exam
    });
  }
);

/* ============================================================
   UPDATE EXAM
============================================================ */

app.put(
  "/api/exams/:id",
  requireAuth,
  requireSchoolAdmin,
  (req, res) => {
    const allExams =
      exams();

    const exam =
      allExams.find(
        e =>
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

    if (
      req.body.title !==
      undefined
    ) {
      exam.title =
        clean(req.body.title);
    }

    if (
      req.body.instructions !==
      undefined
    ) {
      exam.instructions =
        clean(
          req.body.instructions
        );
    }

    if (
      req.body.duration !==
      undefined
    ) {
      exam.duration =
        Number(
          req.body.duration
        );
    }

    if (
      req.body.status !==
      undefined
    ) {
      exam.status =
        req.body.status;
    }

    exam.updatedAt = now();

    writeJson(
      EXAMS_FILE,
      allExams
    );

    res.json({
      ok: true,
      message:
        "Exam updated.",
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
  requireSchoolAdmin,
  (req, res) => {
    let data =
      questions();

    if (
      req.user.role !==
      "superadmin"
    ) {
      data =
        data.filter(
          q =>
            q.schoolId ===
            req.user.schoolId
        );
    }

    res.json({
      ok: true,
      questions: data
    });
  }
);

/* ============================================================
   CREATE QUESTION
============================================================ */

app.post(
  "/api/questions",
  requireAuth,
  requireSchoolAdmin,
  (req, res) => {
    const questionText =
      clean(
        req.body.question
      );

    const options =
      Array.isArray(
        req.body.options
      )
        ? req.body.options
        : [];

    const answer =
      Number(
        req.body.answer
      );

    const subjectId =
      clean(req.body.subjectId);

    const examId =
      clean(req.body.examId);

    const schoolId =
      req.user.role ===
      "superadmin"
        ? clean(req.body.schoolId)
        : req.user.schoolId;

    if (
      !questionText ||
      !schoolId
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Question and school are required."
      });
    }

    if (
      options.length <
      2
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "At least two options are required."
      });
    }

    const allQuestions =
      questions();

    const question = {
      id: id("question"),

      schoolId,

      subjectId,

      examId,

      question:
        questionText,

      options,

      answer:
        Number.isInteger(answer)
          ? answer
          : 0,

      points:
        Number(
          req.body.points ||
          1
        ),

      difficulty:
        clean(
          req.body.difficulty
        ) || "medium",

      tags:
        clean(
          req.body.tags
        ),

      createdBy:
        req.user.id,

      createdAt: now(),

      updatedAt: now()
    };

    allQuestions.push(
      question
    );

    writeJson(
      QUESTIONS_FILE,
      allQuestions
    );

    /*
     * If an examId is supplied,
     * attach the question to the exam.
     */

    if (examId) {
      const allExams =
        exams();

      const exam =
        allExams.find(
          e =>
            e.id ===
            examId
        );

      if (
        exam &&
        sameSchool(
          req,
          exam.schoolId
        )
      ) {
        if (
          !Array.isArray(
            exam.questions
          )
        ) {
          exam.questions = [];
        }

        if (
          !exam.questions.includes(
            question.id
          )
        ) {
          exam.questions.push(
            question.id
          );
        }

        exam.updatedAt =
          now();

        writeJson(
          EXAMS_FILE,
          allExams
        );
      }
    }

    res.status(201).json({
      ok: true,

      message:
        "Question created.",

      question
    });
  }
);

/* ============================================================
   START EXAM
============================================================ */

app.post(
  "/api/exams/:id/start",
  requireAuth,
  requireRole("student"),
  (req, res) => {
    const allExams =
      exams();

    const exam =
      allExams.find(
        e =>
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

    if (
      exam.status !==
      "published"
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "This exam is not available."
      });
    }

    const allResults =
      results();

    const previous =
      allResults.find(
        r =>
          r.examId ===
            exam.id &&
          r.studentId ===
            req.user.id
      );

    if (previous) {
      return res.status(409).json({
        ok: false,
        message:
          "You have already submitted this exam."
      });
    }

    const start =
      new Date();

    const end =
      new Date(
        start.getTime() +
          Number(
            exam.duration ||
            30
          ) *
            60 *
            1000
      );

    const examQuestions =
      questions().filter(
        q =>
          q.examId ===
            exam.id &&
          q.schoolId ===
            req.user.schoolId
      );

    /*
     * Never send the correct
     * answers to the student.
     */

    const safeQuestions =
      examQuestions.map(
        q => ({
          id: q.id,

          question:
            q.question,

          options:
            q.options,

          points:
            q.points || 1,

          difficulty:
            q.difficulty,

          tags: q.tags
        })
      );

    res.json({
      ok: true,

      exam: {
        id: exam.id,

        title: exam.title,

        instructions:
          exam.instructions,

        duration:
          exam.duration,

        startedAt:
          start.toISOString(),

        endsAt:
          end.toISOString(),

        questions:
          safeQuestions
      }
    });
  }
);

/* ============================================================
   SUBMIT EXAM
============================================================ */

app.post(
  "/api/exams/:id/submit",
  requireAuth,
  requireRole("student"),
  (req, res) => {
    const allExams =
      exams();

    const exam =
      allExams.find(
        e =>
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

    const allResults =
      results();

    const already =
      allResults.find(
        r =>
          r.examId ===
            exam.id &&
          r.studentId ===
            req.user.id
      );

    if (already) {
      return res.status(409).json({
        ok: false,
        message:
          "This exam has already been submitted."
      });
    }

    const answers =
      req.body.answers &&
      typeof req.body.answers ===
        "object"
        ? req.body.answers
        : {};

    const examQuestions =
      questions().filter(
        q =>
          q.examId ===
            exam.id &&
          q.schoolId ===
            req.user.schoolId
      );

    let score = 0;

    let total = 0;

    let answered = 0;

    const questionResults = [];

    for (
      const question of
      examQuestions
    ) {
      const points =
        Number(
          question.points ||
          1
        );

      total += points;

      const supplied =
        answers[
          question.id
        ];

      if (
        supplied !==
        undefined &&
        supplied !==
        null &&
        supplied !== ""
      ) {
        answered++;
      }

      const selected =
        Number(supplied);

      const correct =
        selected ===
        Number(
          question.answer
        );

      if (correct) {
        score += points;
      }

      questionResults.push({
        questionId:
          question.id,

        selected:
          Number.isFinite(
            selected
          )
            ? selected
            : null,

        correct
      });
    }

    const percentage =
      total > 0
        ? Number(
            (
              (score /
                total) *
              100
            ).toFixed(2)
          )
        : 0;

    const result = {
      id: id("result"),

      examId:
        exam.id,

      schoolId:
        exam.schoolId,

      studentId:
        req.user.id,

      score,

      total,

      percentage,

      answered,

      submittedAt:
        now(),

      questionResults
    };

    allResults.push(
      result
    );

    writeJson(
      RESULTS_FILE,
      allResults
    );

    res.json({
      ok: true,

      message:
        "Exam submitted successfully.",

      result: {
        id: result.id,

        score,

        total,

        percentage,

        answered,

        submittedAt:
          result.submittedAt
      }
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
    let data =
      results();

    if (
      req.user.role ===
      "student"
    ) {
      data =
        data.filter(
          r =>
            r.studentId ===
            req.user.id
        );
    } else if (
      req.user.role !==
      "superadmin"
    ) {
      data =
        data.filter(
          r =>
            r.schoolId ===
            req.user.schoolId
        );
    }

    res.json({
      ok: true,
      results: data
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
    let data =
      announcements();

    if (
      req.user.role !==
      "superadmin"
    ) {
      data =
        data.filter(
          a =>
            a.schoolId ===
            req.user.schoolId
        );
    }

    data =
      data.sort(
        (a, b) =>
          new Date(b.createdAt) -
          new Date(a.createdAt)
      );

    res.json({
      ok: true,
      announcements: data
    });
  }
);

/* ============================================================
   CREATE ANNOUNCEMENT
============================================================ */

app.post(
  "/api/announcements",
  requireAuth,
  requireSchoolAdmin,
  (req, res) => {
    const title =
      clean(req.body.title);

    const message =
      clean(req.body.message);

    const schoolId =
      req.user.role ===
      "superadmin"
        ? clean(req.body.schoolId)
        : req.user.schoolId;

    if (
      !title ||
      !message ||
      !schoolId
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Title, message and school are required."
      });
    }

    const allAnnouncements =
      announcements();

    const announcement = {
      id: id("announcement"),

      schoolId,

      title,

      message,

      authorId:
        req.user.id,

      createdAt: now(),

      updatedAt: now()
    };

    allAnnouncements.push(
      announcement
    );

    writeJson(
      ANNOUNCEMENTS_FILE,
      allAnnouncements
    );

    res.status(201).json({
      ok: true,

      message:
        "Announcement published.",

      announcement
    });
  }
);

/* ============================================================
   ADMIN SUMMARY
============================================================ */

app.get(
  "/api/admin/summary",
  requireAuth,
  requireSchoolAdmin,
  (req, res) => {
    const schoolId =
      req.user.role ===
      "superadmin"
        ? null
        : req.user.schoolId;

    const allUsers =
      users();

    const allSchools =
      schools();

    const allSubjects =
      subjects();

    const allExams =
      exams();

    const allQuestions =
      questions();

    const allResults =
      results();

    const allAnnouncements =
      announcements();

    let schoolUsers =
      allUsers;

    let schoolSubjects =
      allSubjects;

    let schoolExams =
      allExams;

    let schoolQuestions =
      allQuestions;

    let schoolResults =
      allResults;

    let schoolAnnouncements =
      allAnnouncements;

    if (schoolId) {
      schoolUsers =
        allUsers.filter(
          u =>
            u.schoolId ===
            schoolId
        );

      schoolSubjects =
        allSubjects.filter(
          s =>
            s.schoolId ===
            schoolId
        );

      schoolExams =
        allExams.filter(
          e =>
            e.schoolId ===
            schoolId
        );

      schoolQuestions =
        allQuestions.filter(
          q =>
            q.schoolId ===
            schoolId
        );

      schoolResults =
        allResults.filter(
          r =>
            r.schoolId ===
            schoolId
        );

      schoolAnnouncements =
        allAnnouncements.filter(
          a =>
            a.schoolId ===
            schoolId
        );
    }

    res.json({
      ok: true,

      stats: {
        schools:
          schoolId
            ? 1
            : allSchools.length,

        users:
          schoolUsers.length,

        teachers:
          schoolUsers.filter(
            u =>
              u.role ===
              "teacher"
          ).length,

        students:
          schoolUsers.filter(
            u =>
              u.role ===
              "student"
          ).length,

        admins:
          schoolUsers.filter(
            u =>
              u.role ===
              "school_admin"
          ).length,

        subjects:
          schoolSubjects.length,

        exams:
          schoolExams.length,

        questions:
          schoolQuestions.length,

        results:
          schoolResults.length,

        announcements:
          schoolAnnouncements.length
      }
    });
  }
);

/* ============================================================
   TEACHER DASHBOARD
============================================================ */

app.get(
  "/api/teacher/summary",
  requireAuth,
  requireRole("teacher"),
  (req, res) => {
    const schoolId =
      req.user.schoolId;

    const schoolSubjects =
      subjects().filter(
        s =>
          s.schoolId ===
          schoolId
      );

    const schoolExams =
      exams().filter(
        e =>
          e.schoolId ===
          schoolId
      );

    const schoolQuestions =
      questions().filter(
        q =>
          q.schoolId ===
          schoolId
      );

    const schoolAnnouncements =
      announcements().filter(
        a =>
          a.schoolId ===
          schoolId
      );

    res.json({
      ok: true,

      stats: {
        subjects:
          schoolSubjects.length,

        exams:
          schoolExams.length,

        questions:
          schoolQuestions.length,

        announcements:
          schoolAnnouncements.length
      },

      recentExams:
        schoolExams
          .slice(-5)
          .reverse(),

      recentAnnouncements:
        schoolAnnouncements
          .slice(-5)
          .reverse()
    });
  }
);

/* ============================================================
   STUDENT DASHBOARD
============================================================ */

app.get(
  "/api/student/summary",
  requireAuth,
  requireRole("student"),
  (req, res) => {
    const schoolId =
      req.user.schoolId;

    const schoolExams =
      exams().filter(
        e =>
          e.schoolId ===
            schoolId &&
          e.status ===
            "published"
      );

    const studentResults =
      results().filter(
        r =>
          r.studentId ===
          req.user.id
      );

    const completedExamIds =
      new Set(
        studentResults.map(
          r =>
            r.examId
        )
      );

    const availableExams =
      schoolExams.filter(
        e =>
          !completedExamIds.has(
            e.id
          )
      );

    const schoolAnnouncements =
      announcements()
        .filter(
          a =>
            a.schoolId ===
            schoolId
        )
        .sort(
          (a, b) =>
            new Date(
              b.createdAt
            ) -
            new Date(
              a.createdAt
            )
        );

    const average =
      studentResults.length
        ? Number(
            (
              studentResults.reduce(
                (sum, r) =>
                  sum +
                  Number(
                    r.percentage ||
                    0
                  ),
                0
              ) /
              studentResults.length
            ).toFixed(2)
          )
        : 0;

    res.json({
      ok: true,

      stats: {
        availableExams:
          availableExams.length,

        completedExams:
          studentResults.length,

        averageScore:
          average
      },

      availableExams,

      results:
        studentResults
          .slice()
          .reverse(),

      announcements:
        schoolAnnouncements
          .slice(0, 10)
    });
  }
);

/* ============================================================
   SUPERADMIN - SCHOOLS
============================================================ */

app.get(
  "/api/admin/schools",
  requireAuth,
  requireRole("superadmin"),
  (req, res) => {
    res.json({
      ok: true,
      schools:
        schools()
    });
  }
);

/* ============================================================
   SUPERADMIN - CREATE SCHOOL
============================================================ */

app.post(
  "/api/admin/schools",
  requireAuth,
  requireRole("superadmin"),
  (req, res) => {
    const name =
      clean(req.body.name);

    if (!name) {
      return res.status(400).json({
        ok: false,
        message:
          "School name is required."
      });
    }

    const allSchools =
      schools();

    const school = {
      id: id("school"),

      name,

      motto:
        clean(req.body.motto) ||
        "Smart education for a brighter future.",

      logo:
        clean(req.body.logo),

      primaryColor:
        clean(
          req.body.primaryColor
        ) || "#2563eb",

      secondaryColor:
        clean(
          req.body.secondaryColor
        ) || "#16a34a",

      theme:
        clean(
          req.body.theme
        ) || "light",

      active: true,

      createdAt: now(),

      updatedAt: now()
    };

    allSchools.push(
      school
    );

    writeJson(
      SCHOOLS_FILE,
      allSchools
    );

    res.status(201).json({
      ok: true,
      message:
        "School created.",
      school
    });
  }
);

/* ============================================================
   SUPERADMIN - USERS
============================================================ */

app.get(
  "/api/admin/users",
  requireAuth,
  requireRole("superadmin"),
  (req, res) => {
    res.json({
      ok: true,

      users:
        users().map(
          publicUser
        )
    });
  }
);

/* ============================================================
   SUPERADMIN - PLATFORM SETTINGS
============================================================ */

app.put(
  "/api/admin/settings",
  requireAuth,
  requireRole("superadmin"),
  (req, res) => {
    const config =
      settings();

    if (
      req.body.platformName !==
      undefined
    ) {
      config.platformName =
        clean(
          req.body.platformName
        );
    }

    if (
      req.body.platformDescription !==
      undefined
    ) {
      config.platformDescription =
        clean(
          req.body
            .platformDescription
        );
    }

    if (
      req.body.defaultTheme !==
      undefined
    ) {
      config.defaultTheme =
        clean(
          req.body.defaultTheme
        );
    }

    if (
      req.body.maintenanceMode !==
      undefined
    ) {
      config.maintenanceMode =
        Boolean(
          req.body.maintenanceMode
        );
    }

    writeJson(
      SETTINGS_FILE,
      config
    );

    res.json({
      ok: true,

      message:
        "Platform settings updated.",

      settings:
        config
    });
  }
);

/* ============================================================
   ROLE PAGE ROUTES
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
      extensions: [
        "html"
      ]
    }
  )
);

/* ============================================================
   FRONTEND FALLBACK
============================================================ */

app.get(
  "*",
  (req, res) => {
    if (
      req.path.startsWith(
        "/api/"
      )
    ) {
      return res.status(404).json({
        ok: false,
        message:
          "API route not found."
      });
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

    res.status(404).send(
      "SchoolHub Pro is running, but the requested page was not found."
    );
  }
);

/* ============================================================
   ERROR HANDLER
============================================================ */

app.use(
  (
    err,
    req,
    res,
    next
  ) => {
    console.error(
      "SERVER ERROR:",
      err
    );

    if (
      res.headersSent
    ) {
      return next(err);
    }

    res.status(500).json({
      ok: false,
      message:
        "Internal server error."
    });
  }
);

/* ============================================================
   START SERVER
============================================================ */

const server =
  app.listen(
    PORT,
    HOST,
    () => {
      console.log("");
      console.log(
        "============================================"
      );
      console.log(
        "       SCHOOLHUB PRO SERVER"
      );
      console.log(
        "============================================"
      );
      console.log(
        `Port: ${PORT}`
      );
      console.log(
        `Host: ${HOST}`
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
        "============================================"
      );
      console.log("");
    }
  );

/* ============================================================
   GRACEFUL SHUTDOWN
============================================================ */

function shutdown(signal) {
  console.log(
    `${signal} received. Shutting down...`
  );

  server.close(() => {
    console.log(
      "HTTP server closed."
    );

    process.exit(0);
  });

  setTimeout(() => {
    console.error(
      "Forced shutdown."
    );

    process.exit(1);
  }, 10000);
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
  error => {
    console.error(
      "UNCAUGHT EXCEPTION:",
      error
    );
  }
);

process.on(
  "unhandledRejection",
  error => {
    console.error(
      "UNHANDLED REJECTION:",
      error
    );
  }
);
