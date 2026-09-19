/*
============================================================
 SCHOOLHUB PRO
 COMPLETE WORKING SERVER
============================================================

ROLES
  superadmin
  school_admin
  teacher
  student

DASHBOARDS
  superadmin  -> /superadmin.html
  school_admin -> /admin.html
  teacher -> /teacher.html
  student -> /student.html

FEATURES
  - Multi-school system
  - School isolation
  - Google OAuth
  - Normal login
  - Registration
  - Superadmin
  - School admin
  - Teacher
  - Student
  - School branding
  - Users
  - Subjects
  - Exams / CBT
  - Questions
  - Results
  - Announcements
  - Railway persistent storage
============================================================
*/

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const passport = require("passport");
const GoogleStrategy =
  require("passport-google-oauth20").Strategy;
const dotenv = require("dotenv");
const path = require("path");
const fs = require("fs");

dotenv.config();

const app = express();

/* =========================================================
   CONFIGURATION
========================================================= */

const PORT = Number(process.env.PORT) || 3000;
const HOST = "0.0.0.0";

const NODE_ENV =
  process.env.NODE_ENV || "development";

const IS_PRODUCTION =
  NODE_ENV === "production";

const PUBLIC_DIR =
  path.join(__dirname, "public");

const STORAGE_ROOT =
  process.env.STORAGE_ROOT ||
  path.join(__dirname, "storage");

const DATA_DIR =
  path.join(STORAGE_ROOT, "data");

fs.mkdirSync(PUBLIC_DIR, {
  recursive: true
});

fs.mkdirSync(DATA_DIR, {
  recursive: true
});

console.log("");
console.log("==============================================");
console.log("          SCHOOLHUB PRO SERVER");
console.log("==============================================");
console.log("Environment:", NODE_ENV);
console.log("Port:", PORT);
console.log("Storage:", STORAGE_ROOT);
console.log("==============================================");
console.log("");

/* =========================================================
   DATABASE FILES
========================================================= */

const FILES = {
  users: path.join(DATA_DIR, "users.json"),
  schools: path.join(DATA_DIR, "schools.json"),
  settings: path.join(DATA_DIR, "settings.json"),
  subjects: path.join(DATA_DIR, "subjects.json"),
  exams: path.join(DATA_DIR, "exams.json"),
  questions: path.join(DATA_DIR, "questions.json"),
  results: path.join(DATA_DIR, "results.json"),
  announcements: path.join(
    DATA_DIR,
    "announcements.json"
  )
};

/* =========================================================
   DEFAULT SETTINGS
========================================================= */

const DEFAULT_SETTINGS = {
  platformName: "SchoolHub Pro",
  platformDescription:
    "Smart school management and CBT platform for modern schools.",
  defaultTheme: "light",
  maintenanceMode: false,
  registrationEnabled: true,
  googleAuthEnabled: true,
  paystackEnabled: false
};

/* =========================================================
   DATABASE FUNCTIONS
========================================================= */

function ensureFile(file, defaultData) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(
      file,
      JSON.stringify(defaultData, null, 2),
      "utf8"
    );
  }
}

function readJSON(file, fallback) {
  try {
    if (!fs.existsSync(file)) {
      ensureFile(file, fallback);
      return fallback;
    }

    const content =
      fs.readFileSync(file, "utf8").trim();

    if (!content) {
      return fallback;
    }

    return JSON.parse(content);
  } catch (error) {
    console.error(
      "Database read error:",
      file,
      error.message
    );

    return fallback;
  }
}

function writeJSON(file, data) {
  try {
    fs.writeFileSync(
      file,
      JSON.stringify(data, null, 2),
      "utf8"
    );

    return true;
  } catch (error) {
    console.error(
      "Database write error:",
      file,
      error.message
    );

    return false;
  }
}

function loadDB() {
  return {
    users: readJSON(FILES.users, []),
    schools: readJSON(FILES.schools, []),
    settings: readJSON(
      FILES.settings,
      DEFAULT_SETTINGS
    ),
    subjects: readJSON(
      FILES.subjects,
      []
    ),
    exams: readJSON(
      FILES.exams,
      []
    ),
    questions: readJSON(
      FILES.questions,
      []
    ),
    results: readJSON(
      FILES.results,
      []
    ),
    announcements: readJSON(
      FILES.announcements,
      []
    )
  };
}

function saveDB(db) {
  writeJSON(FILES.users, db.users);
  writeJSON(FILES.schools, db.schools);
  writeJSON(FILES.settings, db.settings);
  writeJSON(FILES.subjects, db.subjects);
  writeJSON(FILES.exams, db.exams);
  writeJSON(FILES.questions, db.questions);
  writeJSON(FILES.results, db.results);
  writeJSON(
    FILES.announcements,
    db.announcements
  );
}

/* Create database files */

ensureFile(FILES.users, []);
ensureFile(FILES.schools, []);
ensureFile(
  FILES.settings,
  DEFAULT_SETTINGS
);
ensureFile(FILES.subjects, []);
ensureFile(FILES.exams, []);
ensureFile(FILES.questions, []);
ensureFile(FILES.results, []);
ensureFile(FILES.announcements, []);

/* =========================================================
   HELPERS
========================================================= */

function id(prefix) {
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

function timestamp() {
  return new Date().toISOString();
}

function text(value) {
  return String(value ?? "").trim();
}

function findSchool(db, schoolId) {
  return db.schools.find(
    (school) => school.id === schoolId
  );
}

function findUser(db, userId) {
  return db.users.find(
    (user) => user.id === userId
  );
}

/* =========================================================
   SAFE USER
========================================================= */

function safeUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    fullName: user.fullName || "",
    username: user.username || "",
    email: user.email || "",
    role: user.role || "",
    schoolId: user.schoolId || null,
    profilePicture:
      user.profilePicture || "",
    active: user.active !== false,
    provider:
      user.provider || "local",
    createdAt:
      user.createdAt || null
  };
}

/* =========================================================
   DASHBOARD REDIRECT
========================================================= */

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

/* =========================================================
   EXPRESS MIDDLEWARE
========================================================= */

app.disable("x-powered-by");

app.use(
  express.json({
    limit: "20mb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "20mb"
  })
);

/* =========================================================
   SESSION
========================================================= */

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET";

app.use(
  session({
    secret: SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

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

/* =========================================================
   PASSPORT
========================================================= */

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(
  (user, done) => {
    done(null, user.id);
  }
);

passport.deserializeUser(
  (userId, done) => {
    const db = loadDB();

    const user =
      findUser(db, userId);

    if (!user) {
      return done(null, false);
    }

    done(null, user);
  }
);

/* =========================================================
   GOOGLE OAUTH CONFIG
========================================================= */

const GOOGLE_CLIENT_ID =
  process.env.GOOGLE_CLIENT_ID || "";

const GOOGLE_CLIENT_SECRET =
  process.env.GOOGLE_CLIENT_SECRET || "";

const GOOGLE_CALLBACK_URL =
  process.env.GOOGLE_CALLBACK_URL ||
  "https://schoolhub-pro-production.up.railway.app/auth/google/callback";

const googleConfigured =
  Boolean(
    GOOGLE_CLIENT_ID &&
      GOOGLE_CLIENT_SECRET &&
      GOOGLE_CALLBACK_URL
  );

console.log(
  "Google Auth:",
  googleConfigured
    ? "CONFIGURED"
    : "NOT CONFIGURED"
);

/* =========================================================
   GOOGLE STRATEGY
========================================================= */

if (googleConfigured) {
  passport.use(
    new GoogleStrategy(
      {
        clientID:
          GOOGLE_CLIENT_ID,

        clientSecret:
          GOOGLE_CLIENT_SECRET,

        callbackURL:
          GOOGLE_CALLBACK_URL
      },

      async (
        accessToken,
        refreshToken,
        profile,
        done
      ) => {
        try {
          const db = loadDB();

          const googleId =
            profile.id;

          const email =
            profile.emails &&
            profile.emails[0]
              ? profile.emails[0].value.toLowerCase()
              : "";

          const fullName =
            profile.displayName ||
            "Google User";

          const profilePicture =
            profile.photos &&
            profile.photos[0]
              ? profile.photos[0].value
              : "";

          /* Existing Google account */

          let user =
            db.users.find(
              (item) =>
                item.googleId ===
                googleId
            );

          if (user) {
            user.fullName =
              user.fullName ||
              fullName;

            user.email =
              user.email ||
              email;

            user.profilePicture =
              profilePicture ||
              user.profilePicture ||
              "";

            user.provider =
              "google";

            user.active = true;

            user.updatedAt =
              timestamp();

            writeJSON(
              FILES.users,
              db.users
            );

            return done(null, user);
          }

          /* Existing local account */

          user =
            db.users.find(
              (item) =>
                item.email &&
                email &&
                item.email.toLowerCase() ===
                  email
            );

          if (user) {
            user.googleId =
              googleId;

            user.provider =
              "google";

            user.profilePicture =
              profilePicture ||
              user.profilePicture ||
              "";

            user.updatedAt =
              timestamp();

            writeJSON(
              FILES.users,
              db.users
            );

            return done(null, user);
          }

          /*
             Do not automatically create an account
             without a school.

             User should register first.
          */

          return done(
            null,
            false,
            {
              message:
                "Google account is not linked to a SchoolHub account."
            }
          );
        } catch (error) {
          console.error(
            "Google strategy error:",
            error
          );

          return done(error);
        }
      }
    )
  );
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function requireAuth(
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

  if (req.user.active === false) {
    return req.logout(() => {
      res.status(403).json({
        ok: false,
        message:
          "Your account has been disabled."
      });
    });
  }

  next();
}

function requireRole(
  ...roles
) {
  return (
    req,
    res,
    next
  ) => {
    if (!req.user) {
      return res.status(401).json({
        ok: false,
        message:
          "Authentication required."
      });
    }

    if (
      !roles.includes(
        req.user.role
      )
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

function requireSchool(
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

  if (!req.user.schoolId) {
    return res.status(403).json({
      ok: false,
      message:
        "This account is not attached to a school."
    });
  }

  next();
}

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
      time: timestamp()
    });
  }
);

/* =========================================================
   PLATFORM
========================================================= */

app.get(
  "/api/platform",
  (req, res) => {
    const db = loadDB();

    res.json({
      ok: true,
      platform:
        db.settings.platformName,
      description:
        db.settings.platformDescription,
      theme:
        db.settings.defaultTheme,
      googleAuth:
        googleConfigured,
      registrationEnabled:
        db.settings
          .registrationEnabled !== false
    });
  }
);

app.get(
  "/api/platform-config",
  (req, res) => {
    const db = loadDB();

    res.json({
      ok: true,
      settings:
        db.settings
    });
  }
);

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/api/me",
  (req, res) => {
    if (!req.user) {
      return res.json({
        ok: true,
        authenticated: false,
        user: null,
        school: null
      });
    }

    const db = loadDB();

    const user =
      findUser(
        db,
        req.user.id
      );

    if (!user) {
      return res.json({
        ok: true,
        authenticated: false,
        user: null,
        school: null
      });
    }

    const school =
      user.schoolId
        ? findSchool(
            db,
            user.schoolId
          )
        : null;

    res.json({
      ok: true,
      authenticated: true,
      user:
        safeUser(user),
      school:
        school || null,
      redirect:
        roleRedirect(user)
    });
  }
);

/* =========================================================
   REGISTER
========================================================= */

app.post(
  "/api/register",
  async (
    req,
    res
  ) => {
    try {
      const db = loadDB();

      if (
        db.settings
          .registrationEnabled ===
        false
      ) {
        return res.status(403).json({
          ok: false,
          message:
            "Registration is currently disabled."
        });
      }

      const schoolName =
        text(
          req.body.schoolName
        );

      const motto =
        text(
          req.body.motto
        );

      const fullName =
        text(
          req.body.fullName
        );

      const username =
        text(
          req.body.username
        ).toLowerCase();

      const email =
        text(
          req.body.email
        ).toLowerCase();

      const password =
        text(
          req.body.password
        );

      if (
        !schoolName ||
        !fullName ||
        !username ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Please fill all required fields."
        });
      }

      if (
        password.length < 6
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Password must contain at least 6 characters."
        });
      }

      if (
        db.users.some(
          (user) =>
            user.email &&
            user.email.toLowerCase() ===
              email
        )
      ) {
        return res.status(409).json({
          ok: false,
          message:
            "Email already exists."
        });
      }

      if (
        db.users.some(
          (user) =>
            user.username &&
            user.username.toLowerCase() ===
              username
        )
      ) {
        return res.status(409).json({
          ok: false,
          message:
            "Username already exists."
        });
      }

      const school = {
        id: id("school"),
        name: schoolName,
        motto,
        logo: "",
        primaryColor:
          "#2563eb",
        secondaryColor:
          "#16a34a",
        theme: "light",
        active: true,
        createdAt:
          timestamp(),
        updatedAt:
          timestamp()
      };

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const user = {
        id: id("user"),
        fullName,
        username,
        email,
        passwordHash,
        role:
          "school_admin",
        schoolId:
          school.id,
        profilePicture: "",
        provider: "local",
        active: true,
        createdAt:
          timestamp(),
        updatedAt:
          timestamp()
      };

      db.schools.push(
        school
      );

      db.users.push(
        user
      );

      saveDB(db);

      req.login(
        user,
        (error) => {
          if (error) {
            console.error(
              "Register login error:",
              error
            );

            return res.status(500).json({
              ok: false,
              message:
                "Account created but login failed."
            });
          }

          res.json({
            ok: true,
            message:
              "School created successfully.",
            user:
              safeUser(user),
            school,
            redirect:
              "/admin.html"
          });
        }
      );
    } catch (error) {
      console.error(
        "Register error:",
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

/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/api/login",
  async (
    req,
    res
  ) => {
    try {
      const identifier =
        text(
          req.body.identifier ||
            req.body.email ||
            req.body.username
        );

      const password =
        text(
          req.body.password
        );

      if (
        !identifier ||
        !password
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Username/email and password are required."
        });
      }

      const db = loadDB();

      const search =
        identifier.toLowerCase();

      const user =
        db.users.find(
          (item) =>
            (
              item.email &&
              item.email.toLowerCase() ===
                search
            ) ||
            (
              item.username &&
              item.username.toLowerCase() ===
                search
            )
        );

      if (!user) {
        return res.status(401).json({
          ok: false,
          message:
            "Invalid username/email or password."
        });
      }

      if (
        user.active === false
      ) {
        return res.status(403).json({
          ok: false,
          message:
            "Your account has been disabled."
        });
      }

      if (
        !user.passwordHash
      ) {
        return res.status(401).json({
          ok: false,
          message:
            "This account uses Google sign-in."
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
            "Invalid username/email or password."
        });
      }

      req.login(
        user,
        (error) => {
          if (error) {
            console.error(
              "Login session error:",
              error
            );

            return res.status(500).json({
              ok: false,
              message:
                "Unable to create login session."
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
    } catch (error) {
      console.error(
        "Login error:",
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

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/api/logout",
  (req, res) => {
    req.logout(
      (error) => {
        if (error) {
          return res.status(500).json({
            ok: false,
            message:
              "Logout failed."
          });
        }

        req.session.destroy(
          () => {
            res.clearCookie(
              "connect.sid"
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
      return res.status(503).send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Google Sign-In</title>
<style>
body{
  margin:0;
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  font-family:Arial,sans-serif;
  background:#f4f7fb;
}
.box{
  width:min(500px,90%);
  background:#fff;
  padding:40px;
  border-radius:20px;
  text-align:center;
  box-shadow:0 20px 60px rgba(0,0,0,.08);
}
a{
  color:#2563eb;
}
</style>
</head>
<body>
<div class="box">
<h2>Google Sign-In is not configured</h2>
<p>Please configure the Google OAuth variables in Railway.</p>
<a href="/login.html">Back to login</a>
</div>
</body>
</html>
`);
    }

    passport.authenticate(
      "google",
      {
        scope: [
          "profile",
          "email"
        ],
        prompt:
          "select_account"
      }
    )(
      req,
      res,
      next
    );
  }
);

/* =========================================================
   GOOGLE CALLBACK
========================================================= */

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
            "Google callback error:",
            error
          );

          return res.redirect(
            "/login.html?error=google_failed"
          );
        }

        if (!user) {
          console.error(
            "Google login rejected:",
            info
          );

          return res.redirect(
            "/login.html?error=google_account_not_linked"
          );
        }

        if (
          user.active === false
        ) {
          return res.redirect(
            "/login.html?error=account_disabled"
          );
        }

        req.logIn(
          user,
          (loginError) => {
            if (loginError) {
              console.error(
                "Google session error:",
                loginError
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
    )(
      req,
      res,
      next
    );
  }
);

/* =========================================================
   SCHOOL
========================================================= */

app.get(
  "/api/school",
  requireAuth,
  requireSchool,
  (req, res) => {
    const db = loadDB();

    const school =
      findSchool(
        db,
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

/* =========================================================
   SCHOOL BRANDING
========================================================= */

app.put(
  "/api/school/branding",
  requireAuth,
  requireRole(
    "school_admin"
  ),
  (req, res) => {
    const db = loadDB();

    const school =
      findSchool(
        db,
        req.user.schoolId
      );

    if (!school) {
      return res.status(404).json({
        ok: false,
        message:
          "School not found."
      });
    }

    if (
      req.body.name !==
      undefined
    ) {
      school.name =
        text(
          req.body.name
        );
    }

    if (
      req.body.motto !==
      undefined
    ) {
      school.motto =
        text(
          req.body.motto
        );
    }

    if (
      req.body.logo !==
      undefined
    ) {
      school.logo =
        text(
          req.body.logo
        );
    }

    if (
      req.body.primaryColor !==
      undefined
    ) {
      school.primaryColor =
        text(
          req.body.primaryColor
        );
    }

    if (
      req.body.secondaryColor !==
      undefined
    ) {
      school.secondaryColor =
        text(
          req.body.secondaryColor
        );
    }

    if (
      req.body.theme !==
      undefined
    ) {
      school.theme =
        text(
          req.body.theme
        ) || "light";
    }

    school.updatedAt =
      timestamp();

    writeJSON(
      FILES.schools,
      db.schools
    );

    res.json({
      ok: true,
      message:
        "School branding updated.",
      school
    });
  }
);

/* =========================================================
   PROFILE
========================================================= */

app.put(
  "/api/profile",
  requireAuth,
  async (
    req,
    res
  ) => {
    try {
      const db = loadDB();

      const user =
        findUser(
          db,
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
          text(
            req.body.fullName
          );
      }

      if (
        req.body.username !==
        undefined
      ) {
        const username =
          text(
            req.body.username
          ).toLowerCase();

        const exists =
          db.users.some(
            (item) =>
              item.id !==
                user.id &&
              item.username ===
                username
          );

        if (exists) {
          return res.status(409).json({
            ok: false,
            message:
              "Username already exists."
          });
        }

        user.username =
          username;
      }

      if (
        req.body.profilePicture !==
        undefined
      ) {
        user.profilePicture =
          text(
            req.body.profilePicture
          );
      }

      if (
        req.body.password
      ) {
        const password =
          String(
            req.body.password
          );

        if (
          password.length < 6
        ) {
          return res.status(400).json({
            ok: false,
            message:
              "Password must contain at least 6 characters."
          });
        }

        user.passwordHash =
          await bcrypt.hash(
            password,
            12
          );
      }

      user.updatedAt =
        timestamp();

      writeJSON(
        FILES.users,
        db.users
      );

      res.json({
        ok: true,
        message:
          "Profile updated successfully.",
        user:
          safeUser(user)
      });
    } catch (error) {
      console.error(
        "Profile error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to update profile."
      });
    }
  }
);

/* =========================================================
   USERS
========================================================= */

app.get(
  "/api/users",
  requireAuth,
  (
    req,
    res
  ) => {
    const db = loadDB();

    let users;

    if (
      req.user.role ===
      "superadmin"
    ) {
      users =
        db.users;
    } else if (
      req.user.role ===
      "school_admin"
    ) {
      users =
        db.users.filter(
          (user) =>
            user.schoolId ===
            req.user.schoolId
        );
    } else {
      users =
        db.users.filter(
          (user) =>
            user.id ===
            req.user.id
        );
    }

    res.json({
      ok: true,
      users:
        users.map(
          safeUser
        )
    });
  }
);

/* =========================================================
   CREATE USER
========================================================= */

app.post(
  "/api/users",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin"
  ),
  async (
    req,
    res
  ) => {
    try {
      const db = loadDB();

      const fullName =
        text(
          req.body.fullName
        );

      const username =
        text(
          req.body.username
        ).toLowerCase();

      const email =
        text(
          req.body.email
        ).toLowerCase();

      const password =
        text(
          req.body.password
        );

      const role =
        text(
          req.body.role
        );

      if (
        !fullName ||
        !username ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Full name, username, email and password are required."
        });
      }

      if (
        password.length < 6
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Password must contain at least 6 characters."
        });
      }

      if (
        ![
          "teacher",
          "student"
        ].includes(role)
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Only teacher and student accounts can be created using this route."
        });
      }

      if (
        db.users.some(
          (user) =>
            user.email &&
            user.email.toLowerCase() ===
              email
        )
      ) {
        return res.status(409).json({
          ok: false,
          message:
            "Email already exists."
        });
      }

      if (
        db.users.some(
          (user) =>
            user.username &&
            user.username.toLowerCase() ===
              username
        )
      ) {
        return res.status(409).json({
          ok: false,
          message:
            "Username already exists."
        });
      }

      let schoolId =
        null;

      if (
        req.user.role ===
        "school_admin"
      ) {
        schoolId =
          req.user.schoolId;
      }

      if (
        req.user.role ===
          "superadmin" &&
        req.body.schoolId
      ) {
        const school =
          findSchool(
            db,
            req.body.schoolId
          );

        if (!school) {
          return res.status(404).json({
            ok: false,
            message:
              "School not found."
          });
        }

        schoolId =
          school.id;
      }

      if (!schoolId) {
        return res.status(400).json({
          ok: false,
          message:
            "School is required."
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const user = {
        id: id("user"),
        fullName,
        username,
        email,
        passwordHash,
        role,
        schoolId,
        profilePicture: "",
        provider: "local",
        active: true,
        createdAt:
          timestamp(),
        updatedAt:
          timestamp()
      };

      db.users.push(
        user
      );

      writeJSON(
        FILES.users,
        db.users
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
        "Create user error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
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
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin"
  ),
  async (
    req,
    res
  ) => {
    try {
      const db = loadDB();

      const user =
        findUser(
          db,
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
        req.user.role ===
          "school_admin" &&
        user.schoolId !==
          req.user.schoolId
      ) {
        return res.status(403).json({
          ok: false,
          message:
            "You cannot manage another school's users."
        });
      }

      if (
        req.body.fullName !==
        undefined
      ) {
        user.fullName =
          text(
            req.body.fullName
          );
      }

      if (
        req.body.email !==
        undefined
      ) {
        const email =
          text(
            req.body.email
          ).toLowerCase();

        const duplicate =
          db.users.some(
            (item) =>
              item.id !==
                user.id &&
              item.email ===
                email
          );

        if (duplicate) {
          return res.status(409).json({
            ok: false,
            message:
              "Email already exists."
          });
        }

        user.email =
          email;
      }

      if (
        req.body.username !==
        undefined
      ) {
        const username =
          text(
            req.body.username
          ).toLowerCase();

        const duplicate =
          db.users.some(
            (item) =>
              item.id !==
                user.id &&
              item.username ===
                username
          );

        if (duplicate) {
          return res.status(409).json({
            ok: false,
            message:
              "Username already exists."
          });
        }

        user.username =
          username;
      }

      if (
        req.user.role ===
        "superadmin"
      ) {
        if (
          req.body.role !==
          undefined
        ) {
          if (
            [
              "superadmin",
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
          req.body.schoolId !==
          undefined
        ) {
          if (
            req.body.schoolId ===
            null
          ) {
            user.schoolId =
              null;
          } else {
            const school =
              findSchool(
                db,
                req.body.schoolId
              );

            if (!school) {
              return res.status(404).json({
                ok: false,
                message:
                  "School not found."
              });
            }

            user.schoolId =
              school.id;
          }
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

      user.updatedAt =
        timestamp();

      writeJSON(
        FILES.users,
        db.users
      );

      res.json({
        ok: true,
        message:
          "User updated successfully.",
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
        message:
          "Unable to update user."
      });
    }
  }
);

/* =========================================================
   DELETE USER
========================================================= */

app.delete(
  "/api/users/:id",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    const index =
      db.users.findIndex(
        (user) =>
          user.id ===
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
      db.users[index];

    if (
      req.user.role ===
        "school_admin" &&
      user.schoolId !==
        req.user.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        message:
          "You cannot delete another school's user."
      });
    }

    if (
      user.role ===
        "superadmin" &&
      req.user.role !==
        "superadmin"
    ) {
      return res.status(403).json({
        ok: false,
        message:
          "You cannot delete a superadmin."
      });
    }

    db.users.splice(
      index,
      1
    );

    writeJSON(
      FILES.users,
      db.users
    );

    res.json({
      ok: true,
      message:
        "User deleted successfully."
    });
  }
);

/* =========================================================
   SUBJECTS
========================================================= */

app.get(
  "/api/subjects",
  requireAuth,
  requireSchool,
  (
    req,
    res
  ) => {
    const db = loadDB();

    const subjects =
      db.subjects.filter(
        (subject) =>
          subject.schoolId ===
          req.user.schoolId
      );

    res.json({
      ok: true,
      subjects
    });
  }
);

app.post(
  "/api/subjects",
  requireAuth,
  requireRole(
    "school_admin",
    "teacher"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    const name =
      text(
        req.body.name
      );

    const code =
      text(
        req.body.code
      );

    if (!name) {
      return res.status(400).json({
        ok: false,
        message:
          "Subject name is required."
      });
    }

    const subject = {
      id: id("subject"),
      schoolId:
        req.user.schoolId,
      name,
      code,
      description:
        text(
          req.body.description
        ),
      createdBy:
        req.user.id,
      createdAt:
        timestamp(),
      updatedAt:
        timestamp()
    };

    db.subjects.push(
      subject
    );

    writeJSON(
      FILES.subjects,
      db.subjects
    );

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
  requireAuth,
  requireRole(
    "school_admin"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    const index =
      db.subjects.findIndex(
        (subject) =>
          subject.id ===
            req.params.id &&
          subject.schoolId ===
            req.user.schoolId
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        message:
          "Subject not found."
      });
    }

    db.subjects.splice(
      index,
      1
    );

    writeJSON(
      FILES.subjects,
      db.subjects
    );

    res.json({
      ok: true,
      message:
        "Subject deleted."
    });
  }
);

/* =========================================================
   EXAMS
========================================================= */

app.get(
  "/api/exams",
  requireAuth,
  requireSchool,
  (
    req,
    res
  ) => {
    const db = loadDB();

    const exams =
      db.exams.filter(
        (exam) =>
          exam.schoolId ===
          req.user.schoolId
      );

    res.json({
      ok: true,
      exams
    });
  }
);

app.post(
  "/api/exams",
  requireAuth,
  requireRole(
    "school_admin",
    "teacher"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    const title =
      text(
        req.body.title
      );

    if (!title) {
      return res.status(400).json({
        ok: false,
        message:
          "Exam title is required."
      });
    }

    const exam = {
      id: id("exam"),
      schoolId:
        req.user.schoolId,
      title,
      subjectId:
        text(
          req.body.subjectId
        ),
      description:
        text(
          req.body.description
        ),
      duration:
        Number(
          req.body.duration
        ) || 30,
      instructions:
        text(
          req.body.instructions
        ),
      status:
        text(
          req.body.status
        ) || "draft",
      createdBy:
        req.user.id,
      createdAt:
        timestamp(),
      updatedAt:
        timestamp()
    };

    db.exams.push(
      exam
    );

    writeJSON(
      FILES.exams,
      db.exams
    );

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
  requireAuth,
  requireRole(
    "school_admin",
    "teacher"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    const exam =
      db.exams.find(
        (item) =>
          item.id ===
            req.params.id &&
          item.schoolId ===
            req.user.schoolId
      );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        message:
          "Exam not found."
      });
    }

    if (
      req.body.title !==
      undefined
    ) {
      exam.title =
        text(
          req.body.title
        );
    }

    if (
      req.body.subjectId !==
      undefined
    ) {
      exam.subjectId =
        text(
          req.body.subjectId
        );
    }

    if (
      req.body.description !==
      undefined
    ) {
      exam.description =
        text(
          req.body.description
        );
    }

    if (
      req.body.duration !==
      undefined
    ) {
      exam.duration =
        Number(
          req.body.duration
        ) || 30;
    }

    if (
      req.body.instructions !==
      undefined
    ) {
      exam.instructions =
        text(
          req.body.instructions
        );
    }

    if (
      req.body.status !==
      undefined
    ) {
      exam.status =
        text(
          req.body.status
        );
    }

    exam.updatedAt =
      timestamp();

    writeJSON(
      FILES.exams,
      db.exams
    );

    res.json({
      ok: true,
      message:
        "Exam updated successfully.",
      exam
    });
  }
);

/* =========================================================
   QUESTIONS
========================================================= */

app.get(
  "/api/questions",
  requireAuth,
  requireSchool,
  (
    req,
    res
  ) => {
    const db = loadDB();

    let questions =
      db.questions.filter(
        (question) =>
          question.schoolId ===
          req.user.schoolId
      );

    if (
      req.query.examId
    ) {
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

app.post(
  "/api/questions",
  requireAuth,
  requireRole(
    "school_admin",
    "teacher"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    const examId =
      text(
        req.body.examId
      );

    const questionText =
      text(
        req.body.question
      );

    if (
      !examId ||
      !questionText
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Exam ID and question are required."
      });
    }

    const exam =
      db.exams.find(
        (exam) =>
          exam.id ===
            examId &&
          exam.schoolId ===
            req.user.schoolId
      );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        message:
          "Exam not found."
      });
    }

    let options =
      req.body.options;

    if (
      !Array.isArray(options)
    ) {
      options = [];
    }

    const question = {
      id: id("question"),
      schoolId:
        req.user.schoolId,
      examId,
      question:
        questionText,
      options,
      answer:
        Number(
          req.body.answer
        ) || 0,
      points:
        Number(
          req.body.points
        ) || 1,
      difficulty:
        text(
          req.body.difficulty
        ) || "medium",
      tags:
        text(
          req.body.tags
        ),
      createdBy:
        req.user.id,
      createdAt:
        timestamp(),
      updatedAt:
        timestamp()
    };

    db.questions.push(
      question
    );

    writeJSON(
      FILES.questions,
      db.questions
    );

    res.status(201).json({
      ok: true,
      message:
        "Question added successfully.",
      question
    });
  }
);

/* =========================================================
   START EXAM
========================================================= */

app.get(
  "/api/exams/:id/start",
  requireAuth,
  requireRole(
    "student"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    const exam =
      db.exams.find(
        (item) =>
          item.id ===
            req.params.id &&
          item.schoolId ===
            req.user.schoolId
      );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        message:
          "Exam not found."
      });
    }

    const questions =
      db.questions.filter(
        (question) =>
          question.examId ===
            exam.id &&
          question.schoolId ===
            req.user.schoolId
      );

    const safeQuestions =
      questions.map(
        (question) => ({
          id:
            question.id,
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
      ok: true,
      exam: {
        id: exam.id,
        title:
          exam.title,
        subjectId:
          exam.subjectId,
        duration:
          exam.duration,
        instructions:
          exam.instructions
      },
      questions:
        safeQuestions
    });
  }
);

/* =========================================================
   SUBMIT EXAM
========================================================= */

app.post(
  "/api/exams/:id/submit",
  requireAuth,
  requireRole(
    "student"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    const exam =
      db.exams.find(
        (item) =>
          item.id ===
            req.params.id &&
          item.schoolId ===
            req.user.schoolId
      );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        message:
          "Exam not found."
      });
    }

    const answers =
      req.body.answers || {};

    const questions =
      db.questions.filter(
        (question) =>
          question.examId ===
            exam.id &&
          question.schoolId ===
            req.user.schoolId
      );

    let score = 0;
    let total = 0;

    const details = [];

    for (
      const question of questions
    ) {
      const points =
        Number(
          question.points
        ) || 1;

      total += points;

      const selected =
        answers[
          question.id
        ];

      const correct =
        Number(
          selected
        ) ===
        Number(
          question.answer
        );

      if (correct) {
        score += points;
      }

      details.push({
        questionId:
          question.id,
        selected:
          selected !==
          undefined
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
      schoolId:
        req.user.schoolId,
      examId:
        exam.id,
      studentId:
        req.user.id,
      score,
      total,
      percentage,
      details,
      submittedAt:
        timestamp()
    };

    db.results.push(
      result
    );

    writeJSON(
      FILES.results,
      db.results
    );

    res.json({
      ok: true,
      message:
        "Exam submitted successfully.",
      result
    });
  }
);

/* =========================================================
   RESULTS
========================================================= */

app.get(
  "/api/results",
  requireAuth,
  requireSchool,
  (
    req,
    res
  ) => {
    const db = loadDB();

    let results =
      db.results.filter(
        (result) =>
          result.schoolId ===
          req.user.schoolId
      );

    if (
      req.user.role ===
      "student"
    ) {
      results =
        results.filter(
          (result) =>
            result.studentId ===
            req.user.id
        );
    }

    if (
      req.query.studentId &&
      req.user.role !==
        "student"
    ) {
      results =
        results.filter(
          (result) =>
            result.studentId ===
            req.query.studentId
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
  requireSchool,
  (
    req,
    res
  ) => {
    const db = loadDB();

    const announcements =
      db.announcements
        .filter(
          (announcement) =>
            announcement.schoolId ===
            req.user.schoolId
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

    res.json({
      ok: true,
      announcements
    });
  }
);

app.post(
  "/api/announcements",
  requireAuth,
  requireRole(
    "school_admin",
    "teacher"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    const title =
      text(
        req.body.title
      );

    const message =
      text(
        req.body.message
      );

    if (
      !title ||
      !message
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "Title and message are required."
      });
    }

    const announcement = {
      id:
        id("announcement"),
      schoolId:
        req.user.schoolId,
      title,
      message,
      createdBy:
        req.user.id,
      createdAt:
        timestamp(),
      updatedAt:
        timestamp()
    };

    db.announcements.push(
      announcement
    );

    writeJSON(
      FILES.announcements,
      db.announcements
    );

    res.status(201).json({
      ok: true,
      message:
        "Announcement published.",
      announcement
    });
  }
);

/* =========================================================
   SCHOOL ADMIN SUMMARY
========================================================= */

app.get(
  "/api/admin/summary",
  requireAuth,
  requireRole(
    "school_admin",
    "superadmin"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    let schoolId =
      req.user.schoolId;

    if (
      req.user.role ===
        "superadmin" &&
      req.query.schoolId
    ) {
      schoolId =
        req.query.schoolId;
    }

    const users =
      db.users.filter(
        (user) =>
          user.schoolId ===
          schoolId
      );

    const subjects =
      db.subjects.filter(
        (subject) =>
          subject.schoolId ===
          schoolId
      );

    const exams =
      db.exams.filter(
        (exam) =>
          exam.schoolId ===
          schoolId
      );

    const questions =
      db.questions.filter(
        (question) =>
          question.schoolId ===
          schoolId
      );

    const results =
      db.results.filter(
        (result) =>
          result.schoolId ===
          schoolId
      );

    const announcements =
      db.announcements.filter(
        (announcement) =>
          announcement.schoolId ===
          schoolId
      );

    res.json({
      ok: true,
      summary: {
        users:
          users.length,
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

/* =========================================================
   TEACHER SUMMARY
========================================================= */

app.get(
  "/api/teacher/summary",
  requireAuth,
  requireRole(
    "teacher"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    const exams =
      db.exams.filter(
        (exam) =>
          exam.schoolId ===
            req.user.schoolId &&
          exam.createdBy ===
            req.user.id
      );

    const questions =
      db.questions.filter(
        (question) =>
          question.schoolId ===
            req.user.schoolId &&
          question.createdBy ===
            req.user.id
      );

    const announcements =
      db.announcements.filter(
        (announcement) =>
          announcement.schoolId ===
            req.user.schoolId &&
          announcement.createdBy ===
            req.user.id
      );

    res.json({
      ok: true,
      summary: {
        exams:
          exams.length,
        questions:
          questions.length,
        announcements:
          announcements.length
      }
    });
  }
);

/* =========================================================
   STUDENT SUMMARY
========================================================= */

app.get(
  "/api/student/summary",
  requireAuth,
  requireRole(
    "student"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    const exams =
      db.exams.filter(
        (exam) =>
          exam.schoolId ===
          req.user.schoolId
      );

    const results =
      db.results.filter(
        (result) =>
          result.schoolId ===
            req.user.schoolId &&
          result.studentId ===
            req.user.id
      );

    const announcements =
      db.announcements.filter(
        (announcement) =>
          announcement.schoolId ===
          req.user.schoolId
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
      }
    });
  }
);

/* =========================================================
   SUPERADMIN - SCHOOLS
========================================================= */

app.get(
  "/api/admin/schools",
  requireAuth,
  requireRole(
    "superadmin"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    const schools =
      db.schools.map(
        (school) => {
          const users =
            db.users.filter(
              (user) =>
                user.schoolId ===
                school.id
            );

          return {
            ...school,

            userCount:
              users.length,

            adminCount:
              users.filter(
                (user) =>
                  user.role ===
                  "school_admin"
              ).length,

            teacherCount:
              users.filter(
                (user) =>
                  user.role ===
                  "teacher"
              ).length,

            studentCount:
              users.filter(
                (user) =>
                  user.role ===
                  "student"
              ).length
          };
        }
      );

    res.json({
      ok: true,
      schools
    });
  }
);

/* =========================================================
   SUPERADMIN - CREATE SCHOOL
========================================================= */

app.post(
  "/api/admin/schools",
  requireAuth,
  requireRole(
    "superadmin"
  ),
  async (
    req,
    res
  ) => {
    try {
      const db = loadDB();

      const schoolName =
        text(
          req.body.name
        );

      const motto =
        text(
          req.body.motto
        );

      const adminName =
        text(
          req.body.adminName
        );

      const adminUsername =
        text(
          req.body.adminUsername
        ).toLowerCase();

      const adminEmail =
        text(
          req.body.adminEmail
        ).toLowerCase();

      const adminPassword =
        text(
          req.body.adminPassword
        );

      if (
        !schoolName ||
        !adminName ||
        !adminUsername ||
        !adminEmail ||
        !adminPassword
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "School and admin details are required."
        });
      }

      if (
        adminPassword.length <
        6
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Admin password must contain at least 6 characters."
        });
      }

      if (
        db.users.some(
          (user) =>
            user.email ===
            adminEmail
        )
      ) {
        return res.status(409).json({
          ok: false,
          message:
            "Admin email already exists."
        });
      }

      if (
        db.users.some(
          (user) =>
            user.username ===
            adminUsername
        )
      ) {
        return res.status(409).json({
          ok: false,
          message:
            "Admin username already exists."
        });
      }

      const school = {
        id:
          id("school"),
        name:
          schoolName,
        motto,
        logo:
          text(
            req.body.logo
          ),
        primaryColor:
          text(
            req.body.primaryColor
          ) ||
          "#2563eb",
        secondaryColor:
          text(
            req.body.secondaryColor
          ) ||
          "#16a34a",
        theme:
          text(
            req.body.theme
          ) ||
          "light",
        active: true,
        createdAt:
          timestamp(),
        updatedAt:
          timestamp()
      };

      const passwordHash =
        await bcrypt.hash(
          adminPassword,
          12
        );

      const admin = {
        id:
          id("user"),
        fullName:
          adminName,
        username:
          adminUsername,
        email:
          adminEmail,
        passwordHash,
        role:
          "school_admin",
        schoolId:
          school.id,
        profilePicture:
          "",
        provider:
          "local",
        active: true,
        createdAt:
          timestamp(),
        updatedAt:
          timestamp()
      };

      db.schools.push(
        school
      );

      db.users.push(
        admin
      );

      saveDB(db);

      res.status(201).json({
        ok: true,
        message:
          "School created successfully.",
        school,
        admin:
          safeUser(admin)
      });
    } catch (error) {
      console.error(
        "Superadmin create school error:",
        error
      );

      res.status(500).json({
        ok: false,
        message:
          "Unable to create school."
      });
    }
  }
);

/* =========================================================
   SUPERADMIN - UPDATE SCHOOL
========================================================= */

app.put(
  "/api/admin/schools/:id",
  requireAuth,
  requireRole(
    "superadmin"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    const school =
      findSchool(
        db,
        req.params.id
      );

    if (!school) {
      return res.status(404).json({
        ok: false,
        message:
          "School not found."
      });
    }

    if (
      req.body.name !==
      undefined
    ) {
      school.name =
        text(
          req.body.name
        );
    }

    if (
      req.body.motto !==
      undefined
    ) {
      school.motto =
        text(
          req.body.motto
        );
    }

    if (
      req.body.logo !==
      undefined
    ) {
      school.logo =
        text(
          req.body.logo
        );
    }

    if (
      req.body.primaryColor !==
      undefined
    ) {
      school.primaryColor =
        text(
          req.body.primaryColor
        );
    }

    if (
      req.body.secondaryColor !==
      undefined
    ) {
      school.secondaryColor =
        text(
          req.body.secondaryColor
        );
    }

    if (
      req.body.theme !==
      undefined
    ) {
      school.theme =
        text(
          req.body.theme
        );
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
      timestamp();

    writeJSON(
      FILES.schools,
      db.schools
    );

    res.json({
      ok: true,
      message:
        "School updated successfully.",
      school
    });
  }
);

/* =========================================================
   SUPERADMIN - ALL USERS
========================================================= */

app.get(
  "/api/admin/users",
  requireAuth,
  requireRole(
    "superadmin"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    const users =
      db.users.map(
        (user) => {
          const school =
            user.schoolId
              ? findSchool(
                  db,
                  user.schoolId
                )
              : null;

          return {
            ...safeUser(user),
            schoolName:
              school
                ? school.name
                : "Platform"
          };
        }
      );

    res.json({
      ok: true,
      users
    });
  }
);

/* =========================================================
   SUPERADMIN - PLATFORM SUMMARY
========================================================= */

app.get(
  "/api/admin/platform-summary",
  requireAuth,
  requireRole(
    "superadmin"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    res.json({
      ok: true,

      summary: {
        schools:
          db.schools.length,

        activeSchools:
          db.schools.filter(
            (school) =>
              school.active !==
              false
          ).length,

        users:
          db.users.length,

        admins:
          db.users.filter(
            (user) =>
              user.role ===
              "school_admin"
          ).length,

        teachers:
          db.users.filter(
            (user) =>
              user.role ===
              "teacher"
          ).length,

        students:
          db.users.filter(
            (user) =>
              user.role ===
              "student"
          ).length,

        exams:
          db.exams.length,

        questions:
          db.questions.length,

        results:
          db.results.length,

        announcements:
          db.announcements.length
      }
    });
  }
);

/* =========================================================
   SUPERADMIN - SETTINGS
========================================================= */

app.put(
  "/api/admin/settings",
  requireAuth,
  requireRole(
    "superadmin"
  ),
  (
    req,
    res
  ) => {
    const db = loadDB();

    const settings = {
      ...db.settings
    };

    if (
      req.body.platformName !==
      undefined
    ) {
      settings.platformName =
        text(
          req.body.platformName
        );
    }

    if (
      req.body.platformDescription !==
      undefined
    ) {
      settings.platformDescription =
        text(
          req.body.platformDescription
        );
    }

    if (
      req.body.defaultTheme !==
      undefined
    ) {
      settings.defaultTheme =
        text(
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

    if (
      req.body.registrationEnabled !==
      undefined
    ) {
      settings.registrationEnabled =
        Boolean(
          req.body.registrationEnabled
        );
    }

    if (
      req.body.googleAuthEnabled !==
      undefined
    ) {
      settings.googleAuthEnabled =
        Boolean(
          req.body.googleAuthEnabled
        );
    }

    if (
      req.body.paystackEnabled !==
      undefined
    ) {
      settings.paystackEnabled =
        Boolean(
          req.body.paystackEnabled
        );
    }

    writeJSON(
      FILES.settings,
      settings
    );

    res.json({
      ok: true,
      message:
        "Platform settings updated.",
      settings
    });
  }
);

/* =========================================================
   DASHBOARD REDIRECT
========================================================= */

app.get(
  "/dashboard",
  (
    req,
    res
  ) => {
    if (!req.user) {
      return res.redirect(
        "/login.html"
      );
    }

    res.redirect(
      roleRedirect(
        req.user
      )
    );
  }
);

/* =========================================================
   STATIC PUBLIC FILES
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
   HOME PAGE
========================================================= */

app.get(
  "/",
  (
    req,
    res
  ) => {
    const index =
      path.join(
        PUBLIC_DIR,
        "index.html"
      );

    if (
      fs.existsSync(index)
    ) {
      return res.sendFile(
        index
      );
    }

    res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>SchoolHub Pro</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{
  margin:0;
  min-height:100vh;
  display:grid;
  place-items:center;
  font-family:Arial,sans-serif;
  background:#f4f7fb;
}
.box{
  width:min(500px,90%);
  background:#fff;
  padding:40px;
  border-radius:20px;
  text-align:center;
  box-shadow:0 20px 60px rgba(0,0,0,.08);
}
a{
  color:#2563eb;
  text-decoration:none;
}
</style>
</head>
<body>
<div class="box">
<h1>SchoolHub Pro</h1>
<p>School management and CBT platform.</p>
<a href="/login.html">Sign in</a>
</div>
</body>
</html>
`);
  }
);

/* =========================================================
   API 404
========================================================= */

app.use(
  "/api",
  (
    req,
    res
  ) => {
    res.status(404).json({
      ok: false,
      message:
        "API endpoint not found."
    });
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

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

    if (
      res.headersSent
    ) {
      return next(
        error
      );
    }

    res.status(500).json({
      ok: false,
      message:
        "Internal server error."
    });
  }
);

/* =========================================================
   SUPERADMIN SETUP
========================================================= */

async function ensureSuperadmin() {
  const email =
    text(
      process.env.SUPERADMIN_EMAIL
    ).toLowerCase();

  const username =
    text(
      process.env.SUPERADMIN_USERNAME
    ).toLowerCase() ||
    "superadmin";

  const password =
    text(
      process.env.SUPERADMIN_PASSWORD
    );

  const fullName =
    text(
      process.env.SUPERADMIN_NAME
    ) ||
    "SchoolHub Super Admin";

  if (
    !email ||
    !password
  ) {
    console.log(
      "Superadmin environment variables not configured."
    );

    return;
  }

  const db = loadDB();

  let user =
    db.users.find(
      (item) =>
        item.email &&
        item.email.toLowerCase() ===
          email
    );

  if (!user) {
    user =
      db.users.find(
        (item) =>
          item.username &&
          item.username.toLowerCase() ===
            username
      );
  }

  if (user) {
    user.role =
      "superadmin";

    user.schoolId =
      null;

    user.active =
      true;

    user.updatedAt =
      timestamp();

    writeJSON(
      FILES.users,
      db.users
    );

    console.log(
      "Superadmin verified:",
      user.email
    );

    return;
  }

  const passwordHash =
    await bcrypt.hash(
      password,
      12
    );

  const superadmin = {
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
    active: true,
    createdAt:
      timestamp(),
    updatedAt:
      timestamp()
  };

  db.users.push(
    superadmin
  );

  writeJSON(
    FILES.users,
    db.users
  );

  console.log(
    "Superadmin created:",
    email
  );
}

/* =========================================================
   START SERVER
========================================================= */

let server = null;

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
            "=============================================="
          );
          console.log(
            "       SCHOOLHUB PRO IS ONLINE"
          );
          console.log(
            "=============================================="
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
            `Google Callback: ${GOOGLE_CALLBACK_URL}`
          );
          console.log(
            "=============================================="
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

/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

function shutdown(
  signal
) {
  console.log(
    `Received ${signal}. Shutting down...`
  );

  if (!server) {
    process.exit(0);
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
      console.log(
        "Forced shutdown."
      );

      process.exit(1);
    },
    10000
  ).unref();
}

process.on(
  "SIGTERM",
  () =>
    shutdown(
      "SIGTERM"
    )
);

process.on(
  "SIGINT",
  () =>
    shutdown(
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

/* =========================================================
   RUN
========================================================= */

startServer();
