/*
===========================================================
 SCHOOLHUB PRO
 Multi-School School Management + CBT Platform
 COMPLETE SERVER
===========================================================

ROLES
- superadmin
- school_admin
- teacher
- student

STORAGE
- JSON files
- Railway persistent volume supported

GOOGLE AUTH
- Passport Google OAuth 2.0
- Server-side OAuth
- Callback:
  /auth/google/callback

RAILWAY
Recommended:
STORAGE_ROOT=/app/storage
GOOGLE_CALLBACK_URL=https://schoolhub-pro-production.up.railway.app/auth/google/callback
===========================================================
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

const app = express();

/* =========================================================
   BASIC CONFIG
========================================================= */

const PORT = Number(process.env.PORT) || 3000;
const HOST = "0.0.0.0";

const IS_PRODUCTION = process.env.NODE_ENV === "production";

const STORAGE_ROOT =
  process.env.STORAGE_ROOT ||
  path.join(__dirname, "storage");

const DATA_DIR = path.join(STORAGE_ROOT, "data");
const PUBLIC_DIR = path.join(__dirname, "public");

fs.mkdirSync(STORAGE_ROOT, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(PUBLIC_DIR, { recursive: true });

console.log("");
console.log("=================================================");
console.log(" SCHOOLHUB PRO SERVER");
console.log("=================================================");
console.log("Environment:", process.env.NODE_ENV || "development");
console.log("Port:", PORT);
console.log("Storage:", STORAGE_ROOT);
console.log("Public:", PUBLIC_DIR);
console.log("=================================================");
console.log("");

/* =========================================================
   JSON DATABASE FILES
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

/* =========================================================
   DEFAULT DATA
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
   DATABASE HELPERS
========================================================= */

function ensureFile(file, defaultValue = []) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(
      file,
      JSON.stringify(defaultValue, null, 2),
      "utf8"
    );
  }
}

function readJSON(file, fallback = []) {
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
      return fallback;
    }

    return JSON.parse(raw);
  } catch (error) {
    console.error("JSON READ ERROR:", file);
    console.error(error.message);
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
    console.error("JSON WRITE ERROR:", file);
    console.error(error.message);
    return false;
  }
}

function loadDB() {
  return {
    users: readJSON(FILES.users, []),
    schools: readJSON(FILES.schools, []),
    settings: readJSON(FILES.settings, DEFAULT_SETTINGS),
    subjects: readJSON(FILES.subjects, []),
    exams: readJSON(FILES.exams, []),
    questions: readJSON(FILES.questions, []),
    results: readJSON(FILES.results, []),
    announcements: readJSON(FILES.announcements, [])
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
  writeJSON(FILES.announcements, db.announcements);
}

/* Make sure all files exist */

ensureFile(FILES.users, []);
ensureFile(FILES.schools, []);
ensureFile(FILES.settings, DEFAULT_SETTINGS);
ensureFile(FILES.subjects, []);
ensureFile(FILES.exams, []);
ensureFile(FILES.questions, []);
ensureFile(FILES.results, []);
ensureFile(FILES.announcements, []);

/* =========================================================
   ID / TIME HELPERS
========================================================= */

function createId(prefix = "id") {
  return (
    prefix +
    "_" +
    Date.now().toString(36) +
    "_" +
    Math.random().toString(36).slice(2, 10)
  );
}

function now() {
  return new Date().toISOString();
}

function cleanString(value) {
  return String(value || "").trim();
}

/* =========================================================
   EXPRESS
========================================================= */

app.disable("x-powered-by");

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

/* =========================================================
   SESSION
========================================================= */

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "CHANGE_THIS_SESSION_SECRET_IN_PRODUCTION";

app.use(
  session({
    secret: SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      secure: IS_PRODUCTION,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7
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

passport.deserializeUser((userId, done) => {
  const db = loadDB();

  const user = db.users.find(
    (item) => item.id === userId
  );

  if (!user) {
    return done(null, false);
  }

  done(null, user);
});

/* =========================================================
   GOOGLE CONFIG
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
  googleConfigured ? "CONFIGURED" : "NOT CONFIGURED"
);

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
          const db = loadDB();

          const googleId = profile.id;

          const email =
            profile.emails &&
            profile.emails[0]
              ? profile.emails[0].value.toLowerCase()
              : "";

          const displayName =
            profile.displayName ||
            (profile.name
              ? `${profile.name.givenName || ""} ${
                  profile.name.familyName || ""
                }`.trim()
              : "Google User");

          const profilePicture =
            profile.photos &&
            profile.photos[0]
              ? profile.photos[0].value
              : "";

          let user = db.users.find(
            (item) =>
              item.googleId === googleId
          );

          /* ---------------------------------------------
             Existing Google user
          --------------------------------------------- */

          if (user) {
            user.fullName =
              user.fullName || displayName;

            user.email =
              user.email || email;

            user.profilePicture =
              profilePicture ||
              user.profilePicture ||
              "";

            user.provider = "google";
            user.active = true;
            user.updatedAt = now();

            writeJSON(FILES.users, db.users);

            return done(null, user);
          }

          /* ---------------------------------------------
             Match existing local account by email
          --------------------------------------------- */

          user = db.users.find(
            (item) =>
              item.email &&
              email &&
              item.email.toLowerCase() === email
          );

          if (user) {
            user.googleId = googleId;
            user.provider = "google";
            user.profilePicture =
              profilePicture ||
              user.profilePicture ||
              "";
            user.updatedAt = now();

            writeJSON(FILES.users, db.users);

            return done(null, user);
          }

          /*
            IMPORTANT:
            Google does NOT automatically create a random
            school account.

            A person should first register normally.
          */

          return done(
            null,
            false,
            {
              message:
                "No SchoolHub account is linked to this Google account. Please register first."
            }
          );
        } catch (error) {
          console.error("GOOGLE STRATEGY ERROR:");
          console.error(error);

          return done(error);
        }
      }
    )
  );
}

/* =========================================================
   USER SAFE OBJECT
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
    profilePicture: user.profilePicture || "",
    active: user.active !== false,
    provider: user.provider || "local",
    createdAt: user.createdAt || null
  };
}

/* =========================================================
   ROLE REDIRECT
========================================================= */

function roleRedirect(user) {
  if (!user) {
    return "/login.html";
  }

  switch (user.role) {
    case "superadmin":
      return "/superadmin.html";

    case "school_admin":
      return "/admin.html";

    case "teacher":
      return "/teacher.html";

    case "student":
      return "/student.html";

    default:
      return "/login.html";
  }
}

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function requireAuth(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      ok: false,
      message: "Authentication required"
    });
  }

  if (req.user.active === false) {
    req.logout(() => {});

    return res.status(403).json({
      ok: false,
      message: "Your account has been disabled."
    });
  }

  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        ok: false,
        message: "Authentication required"
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        ok: false,
        message: "You do not have permission to perform this action."
      });
    }

    next();
  };
}

function requireSchoolUser(req, res, next) {
  if (!req.user) {
    return res.status(401).json({
      ok: false,
      message: "Authentication required"
    });
  }

  if (!req.user.schoolId) {
    return res.status(403).json({
      ok: false,
      message: "This account is not attached to a school."
    });
  }

  next();
}

/* =========================================================
   GET SCHOOL
========================================================= */

function getSchool(db, schoolId) {
  return db.schools.find(
    (school) => school.id === schoolId
  );
}

/* =========================================================
   SUPERADMIN CREATION
========================================================= */

async function ensureSuperadmin() {
  const email = cleanString(
    process.env.SUPERADMIN_EMAIL
  ).toLowerCase();

  const username = cleanString(
    process.env.SUPERADMIN_USERNAME ||
      "superadmin"
  ).toLowerCase();

  const password = cleanString(
    process.env.SUPERADMIN_PASSWORD
  );

  const fullName =
    cleanString(
      process.env.SUPERADMIN_NAME
    ) || "SchoolHub Super Admin";

  if (!email || !password) {
    console.log(
      "Superadmin env not configured. Existing superadmin accounts will still work."
    );

    return;
  }

  const db = loadDB();

  let user =
    db.users.find(
      (item) =>
        item.email &&
        item.email.toLowerCase() === email
    ) ||
    db.users.find(
      (item) =>
        item.username &&
        item.username.toLowerCase() === username
    );

  if (user) {
    user.role = "superadmin";
    user.active = true;
    user.schoolId = null;
    user.updatedAt = now();

    writeJSON(FILES.users, db.users);

    console.log(
      "Superadmin account verified:",
      user.email
    );

    return;
  }

  const passwordHash =
    await bcrypt.hash(password, 12);

  user = {
    id: createId("user"),
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

  db.users.push(user);

  writeJSON(FILES.users, db.users);

  console.log(
    "Superadmin account created:",
    email
  );
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    status: "online",
    service: "SchoolHub Pro",
    version: "5.1.0",
    environment:
      process.env.NODE_ENV || "development",
    port: PORT,
    storage: STORAGE_ROOT,
    googleAuth: googleConfigured
      ? "CONFIGURED"
      : "NOT CONFIGURED",
    time: now()
  });
});

/* =========================================================
   PLATFORM INFO
========================================================= */

app.get("/api/platform", (req, res) => {
  const db = loadDB();

  res.json({
    ok: true,
    platform: db.settings.platformName,
    description:
      db.settings.platformDescription,
    theme: db.settings.defaultTheme,
    googleAuth: googleConfigured,
    registrationEnabled:
      db.settings.registrationEnabled !== false
  });
});

app.get("/api/platform-config", (req, res) => {
  const db = loadDB();

  res.json({
    ok: true,
    settings: db.settings
  });
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get("/api/me", (req, res) => {
  if (!req.user) {
    return res.json({
      ok: true,
      authenticated: false,
      user: null
    });
  }

  const db = loadDB();

  const user = db.users.find(
    (item) => item.id === req.user.id
  );

  if (!user) {
    return res.json({
      ok: true,
      authenticated: false,
      user: null
    });
  }

  let school = null;

  if (user.schoolId) {
    school = getSchool(
      db,
      user.schoolId
    );
  }

  res.json({
    ok: true,
    authenticated: true,
    user: safeUser(user),
    school: school || null,
    redirect: roleRedirect(user)
  });
});

/* =========================================================
   REGISTER SCHOOL + SCHOOL ADMIN
========================================================= */

app.post("/api/register", async (req, res) => {
  try {
    const db = loadDB();

    if (
      db.settings.registrationEnabled === false
    ) {
      return res.status(403).json({
        ok: false,
        message:
          "Registration is currently disabled."
      });
    }

    const schoolName =
      cleanString(req.body.schoolName);

    const motto =
      cleanString(req.body.motto);

    const fullName =
      cleanString(req.body.fullName);

    const username =
      cleanString(req.body.username)
        .toLowerCase();

    const email =
      cleanString(req.body.email)
        .toLowerCase();

    const password =
      cleanString(req.body.password);

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

    if (password.length < 6) {
      return res.status(400).json({
        ok: false,
        message:
          "Password must contain at least 6 characters."
      });
    }

    const emailExists =
      db.users.some(
        (user) =>
          user.email &&
          user.email.toLowerCase() === email
      );

    if (emailExists) {
      return res.status(409).json({
        ok: false,
        message:
          "An account with this email already exists."
      });
    }

    const usernameExists =
      db.users.some(
        (user) =>
          user.username &&
          user.username.toLowerCase() ===
            username
      );

    if (usernameExists) {
      return res.status(409).json({
        ok: false,
        message:
          "That username is already in use."
      });
    }

    const school = {
      id: createId("school"),
      name: schoolName,
      motto,
      logo: "",
      primaryColor: "#2563eb",
      secondaryColor: "#16a34a",
      theme: "light",
      active: true,
      createdAt: now(),
      updatedAt: now()
    };

    const passwordHash =
      await bcrypt.hash(password, 12);

    const user = {
      id: createId("user"),
      fullName,
      username,
      email,
      passwordHash,
      role: "school_admin",
      schoolId: school.id,
      profilePicture: "",
      provider: "local",
      active: true,
      createdAt: now(),
      updatedAt: now()
    };

    db.schools.push(school);
    db.users.push(user);

    saveDB(db);

    req.login(user, (loginError) => {
      if (loginError) {
        console.error(loginError);

        return res.status(500).json({
          ok: false,
          message:
            "Account created but automatic login failed."
        });
      }

      res.json({
        ok: true,
        message:
          "School account created successfully.",
        user: safeUser(user),
        school,
        redirect: "/admin.html"
      });
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      ok: false,
      message:
        "Unable to create the school account."
    });
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {
  try {
    const identifier =
      cleanString(req.body.identifier);

    const password =
      cleanString(req.body.password);

    if (!identifier || !password) {
      return res.status(400).json({
        ok: false,
        message:
          "Username/email and password are required."
      });
    }

    const db = loadDB();

    const value =
      identifier.toLowerCase();

    const user =
      db.users.find(
        (item) =>
          (item.email &&
            item.email.toLowerCase() === value) ||
          (item.username &&
            item.username.toLowerCase() ===
              value)
      );

    if (!user) {
      return res.status(401).json({
        ok: false,
        message:
          "Invalid username/email or password."
      });
    }

    if (user.active === false) {
      return res.status(403).json({
        ok: false,
        message:
          "Your account has been disabled."
      });
    }

    if (!user.passwordHash) {
      return res.status(401).json({
        ok: false,
        message:
          "This account uses Google sign-in. Please use Google."
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
        message:
          "Invalid username/email or password."
      });
    }

    req.login(user, (error) => {
      if (error) {
        console.error(
          "SESSION LOGIN ERROR:",
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
        message: "Login successful.",
        user: safeUser(user),
        redirect: roleRedirect(user)
      });
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      ok: false,
      message:
        "An internal error occurred during login."
    });
  }
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/logout", (req, res) => {
  req.logout((error) => {
    if (error) {
      console.error(error);

      return res.status(500).json({
        ok: false,
        message: "Logout failed."
      });
    }

    req.session.destroy(() => {
      res.clearCookie("connect.sid");

      res.json({
        ok: true,
        message: "Logged out successfully."
      });
    });
  });
});

/* =========================================================
   GOOGLE LOGIN
========================================================= */

app.get("/auth/google", (req, res, next) => {
  if (!googleConfigured) {
    return res.status(503).send(`
      <!doctype html>
      <html>
      <head>
        <title>Google Sign-In</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            background: #f4f7fb;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
          }
          .box {
            background: white;
            padding: 40px;
            border-radius: 16px;
            max-width: 520px;
            text-align: center;
            box-shadow: 0 15px 40px rgba(0,0,0,.08);
          }
        </style>
      </head>
      <body>
        <div class="box">
          <h2>Google Sign-In is not configured</h2>
          <p>Please configure the Google OAuth environment variables on the server.</p>
          <a href="/login.html">Back to Login</a>
        </div>
      </body>
      </html>
    `);
  }

  passport.authenticate("google", {
    scope: [
      "profile",
      "email"
    ],
    prompt: "select_account"
  })(req, res, next);
});

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
          console.error(
            "GOOGLE LOGIN FAILED:",
            info
          );

          return res.redirect(
            "/login.html?error=google_account_not_linked"
          );
        }

        if (user.active === false) {
          return res.redirect(
            "/login.html?error=account_disabled"
          );
        }

        req.logIn(user, (loginError) => {
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
        });
      }
    )(req, res, next);
  }
);

/* =========================================================
   SCHOOL
========================================================= */

app.get(
  "/api/school",
  requireAuth,
  requireSchoolUser,
  (req, res) => {
    const db = loadDB();

    const school = getSchool(
      db,
      req.user.schoolId
    );

    if (!school) {
      return res.status(404).json({
        ok: false,
        message: "School not found."
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
  requireRole("school_admin"),
  (req, res) => {
    const db = loadDB();

    const school = getSchool(
      db,
      req.user.schoolId
    );

    if (!school) {
      return res.status(404).json({
        ok: false,
        message: "School not found."
      });
    }

    if (req.body.name !== undefined) {
      school.name =
        cleanString(req.body.name);
    }

    if (req.body.motto !== undefined) {
      school.motto =
        cleanString(req.body.motto);
    }

    if (req.body.logo !== undefined) {
      school.logo =
        cleanString(req.body.logo);
    }

    if (req.body.primaryColor !== undefined) {
      school.primaryColor =
        cleanString(req.body.primaryColor);
    }

    if (req.body.secondaryColor !== undefined) {
      school.secondaryColor =
        cleanString(req.body.secondaryColor);
    }

    if (req.body.theme !== undefined) {
      school.theme =
        cleanString(req.body.theme) ||
        "light";
    }

    school.updatedAt = now();

    writeJSON(FILES.schools, db.schools);

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
  (req, res) => {
    const db = loadDB();

    const user = db.users.find(
      (item) => item.id === req.user.id
    );

    if (!user) {
      return res.status(404).json({
        ok: false,
        message: "User not found."
      });
    }

    if (req.body.fullName !== undefined) {
      user.fullName =
        cleanString(req.body.fullName);
    }

    if (req.body.username !== undefined) {
      const username =
        cleanString(req.body.username)
          .toLowerCase();

      const duplicate =
        db.users.some(
          (item) =>
            item.id !== user.id &&
            item.username === username
        );

      if (duplicate) {
        return res.status(409).json({
          ok: false,
          message:
            "That username is already in use."
        });
      }

      user.username = username;
    }

    if (
      req.body.profilePicture !== undefined
    ) {
      user.profilePicture =
        cleanString(
          req.body.profilePicture
        );
    }

    if (req.body.password) {
      if (String(req.body.password).length < 6) {
        return res.status(400).json({
          ok: false,
          message:
            "New password must contain at least 6 characters."
        });
      }

      user.passwordHash =
        awaitHash(req.body.password);
    }

    user.updatedAt = now();

    writeJSON(FILES.users, db.users);

    res.json({
      ok: true,
      message:
        "Profile updated successfully.",
      user: safeUser(user)
    });
  }
);

/*
 Helper for synchronous-looking profile route.
 bcrypt hashing is async, so this function is replaced
 below by a promise-aware route implementation.
*/

function awaitHash(password) {
  /*
    This function is intentionally not used to block.
    The profile route below is replaced after declaration.
  */
  return password;
}

/* =========================================================
   REPLACE PROFILE ROUTE WITH ASYNC VERSION
========================================================= */

app._router.stack =
  app._router.stack.filter(
    (layer) => {
      return !(
        layer.route &&
        layer.route.path === "/api/profile"
      );
    }
  );

app.put(
  "/api/profile",
  requireAuth,
  async (req, res) => {
    try {
      const db = loadDB();

      const user = db.users.find(
        (item) => item.id === req.user.id
      );

      if (!user) {
        return res.status(404).json({
          ok: false,
          message: "User not found."
        });
      }

      if (req.body.fullName !== undefined) {
        user.fullName =
          cleanString(req.body.fullName);
      }

      if (req.body.username !== undefined) {
        const username =
          cleanString(req.body.username)
            .toLowerCase();

        const duplicate =
          db.users.some(
            (item) =>
              item.id !== user.id &&
              item.username === username
          );

        if (duplicate) {
          return res.status(409).json({
            ok: false,
            message:
              "That username is already in use."
          });
        }

        user.username = username;
      }

      if (
        req.body.profilePicture !== undefined
      ) {
        user.profilePicture =
          cleanString(
            req.body.profilePicture
          );
      }

      if (req.body.password) {
        const password =
          String(req.body.password);

        if (password.length < 6) {
          return res.status(400).json({
            ok: false,
            message:
              "New password must contain at least 6 characters."
          });
        }

        user.passwordHash =
          await bcrypt.hash(password, 12);
      }

      user.updatedAt = now();

      writeJSON(FILES.users, db.users);

      res.json({
        ok: true,
        message:
          "Profile updated successfully.",
        user: safeUser(user)
      });
    } catch (error) {
      console.error(
        "PROFILE UPDATE ERROR:",
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

/*
 School admin:
 - can create teacher/student
 - can manage users in own school

 Superadmin:
 - can manage users across platform
*/

app.get(
  "/api/users",
  requireAuth,
  (req, res) => {
    const db = loadDB();

    let users = [];

    if (req.user.role === "superadmin") {
      users = db.users;
    } else if (
      req.user.role === "school_admin"
    ) {
      users = db.users.filter(
        (user) =>
          user.schoolId === req.user.schoolId
      );
    } else {
      users = db.users.filter(
        (user) => user.id === req.user.id
      );
    }

    res.json({
      ok: true,
      users: users.map(safeUser)
    });
  }
);

app.post(
  "/api/users",
  requireAuth,
  requireRole(
    "superadmin",
    "school_admin"
  ),
  async (req, res) => {
    try {
      const db = loadDB();

      const fullName =
        cleanString(req.body.fullName);

      const username =
        cleanString(req.body.username)
          .toLowerCase();

      const email =
        cleanString(req.body.email)
          .toLowerCase();

      const password =
        cleanString(req.body.password);

      let role =
        cleanString(req.body.role);

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

      if (password.length < 6) {
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
            "Only teacher and student accounts can be created here."
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

      let schoolId = null;

      if (req.user.role === "school_admin") {
        schoolId = req.user.schoolId;
      }

      if (
        req.user.role === "superadmin" &&
        req.body.schoolId
      ) {
        const school = getSchool(
          db,
          req.body.schoolId
        );

        if (!school) {
          return res.status(404).json({
            ok: false,
            message:
              "Selected school was not found."
          });
        }

        schoolId = school.id;
      }

      if (!schoolId) {
        return res.status(400).json({
          ok: false,
          message:
            "A school must be selected."
        });
      }

      const passwordHash =
        await bcrypt.hash(password, 12);

      const user = {
        id: createId("user"),
        fullName,
        username,
        email,
        passwordHash,
        role,
        schoolId,
        profilePicture: "",
        provider: "local",
        active: true,
        createdAt: now(),
        updatedAt: now()
      };

      db.users.push(user);

      writeJSON(FILES.users, db.users);

      res.status(201).json({
        ok: true,
        message:
          `${role} account created successfully.`,
        user: safeUser(user)
      });
    } catch (error) {
      console.error(
        "CREATE USER ERROR:",
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
  async (req, res) => {
    try {
      const db = loadDB();

      const user = db.users.find(
        (item) =>
          item.id === req.params.id
      );

      if (!user) {
        return res.status(404).json({
          ok: false,
          message: "User not found."
        });
      }

      if (
        req.user.role === "school_admin" &&
        user.schoolId !== req.user.schoolId
      ) {
        return res.status(403).json({
          ok: false,
          message:
            "You cannot manage users from another school."
        });
      }

      if (
        req.body.fullName !== undefined
      ) {
        user.fullName =
          cleanString(
            req.body.fullName
          );
      }

      if (
        req.body.email !== undefined
      ) {
        const email =
          cleanString(
            req.body.email
          ).toLowerCase();

        const duplicate =
          db.users.some(
            (item) =>
              item.id !== user.id &&
              item.email === email
          );

        if (duplicate) {
          return res.status(409).json({
            ok: false,
            message:
              "Email already belongs to another user."
          });
        }

        user.email = email;
      }

      if (
        req.body.username !== undefined
      ) {
        const username =
          cleanString(
            req.body.username
          ).toLowerCase();

        const duplicate =
          db.users.some(
            (item) =>
              item.id !== user.id &&
              item.username === username
          );

        if (duplicate) {
          return res.status(409).json({
            ok: false,
            message:
              "Username already belongs to another user."
          });
        }

        user.username = username;
      }

      if (
        req.body.role !== undefined &&
        req.user.role === "superadmin"
      ) {
        if (
          [
            "superadmin",
            "school_admin",
            "teacher",
            "student"
          ].includes(req.body.role)
        ) {
          user.role = req.body.role;
        }
      }

      if (
        req.body.schoolId !== undefined &&
        req.user.role === "superadmin"
      ) {
        if (req.body.schoolId === null) {
          user.schoolId = null;
        } else {
          const school =
            getSchool(
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

      if (
        req.body.active !== undefined
      ) {
        user.active =
          Boolean(req.body.active);
      }

      if (req.body.password) {
        user.passwordHash =
          await bcrypt.hash(
            String(req.body.password),
            12
          );
      }

      user.updatedAt = now();

      writeJSON(FILES.users, db.users);

      res.json({
        ok: true,
        message:
          "User updated successfully.",
        user: safeUser(user)
      });
    } catch (error) {
      console.error(
        "UPDATE USER ERROR:",
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
  (req, res) => {
    const db = loadDB();

    const index =
      db.users.findIndex(
        (item) =>
          item.id === req.params.id
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        message: "User not found."
      });
    }

    const user =
      db.users[index];

    if (
      req.user.role === "school_admin" &&
      user.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        ok: false,
        message:
          "You cannot delete users from another school."
      });
    }

    if (
      user.role === "superadmin" &&
      req.user.role !== "superadmin"
    ) {
      return res.status(403).json({
        ok: false,
        message:
          "Superadmin accounts cannot be deleted here."
      });
    }

    db.users.splice(index, 1);

    writeJSON(FILES.users, db.users);

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
  requireSchoolUser,
  (req, res) => {
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
  (req, res) => {
    const db = loadDB();

    const name =
      cleanString(req.body.name);

    const code =
      cleanString(req.body.code);

    if (!name) {
      return res.status(400).json({
        ok: false,
        message:
          "Subject name is required."
      });
    }

    const subject = {
      id: createId("subject"),
      schoolId: req.user.schoolId,
      name,
      code,
      description:
        cleanString(
          req.body.description
        ),
      createdBy: req.user.id,
      createdAt: now(),
      updatedAt: now()
    };

    db.subjects.push(subject);

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
  requireRole("school_admin"),
  (req, res) => {
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

    db.subjects.splice(index, 1);

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
  requireSchoolUser,
  (req, res) => {
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
  (req, res) => {
    const db = loadDB();

    const title =
      cleanString(req.body.title);

    const subjectId =
      cleanString(req.body.subjectId);

    if (!title) {
      return res.status(400).json({
        ok: false,
        message:
          "Exam title is required."
      });
    }

    const exam = {
      id: createId("exam"),
      schoolId: req.user.schoolId,
      title,
      subjectId,
      description:
        cleanString(
          req.body.description
        ),
      duration:
        Number(req.body.duration) || 30,
      instructions:
        cleanString(
          req.body.instructions
        ),
      status:
        cleanString(
          req.body.status
        ) || "draft",
      createdBy: req.user.id,
      createdAt: now(),
      updatedAt: now()
    };

    db.exams.push(exam);

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
  (req, res) => {
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

    if (req.body.title !== undefined) {
      exam.title =
        cleanString(
          req.body.title
        );
    }

    if (
      req.body.subjectId !== undefined
    ) {
      exam.subjectId =
        cleanString(
          req.body.subjectId
        );
    }

    if (
      req.body.description !==
      undefined
    ) {
      exam.description =
        cleanString(
          req.body.description
        );
    }

    if (
      req.body.duration !==
      undefined
    ) {
      exam.duration =
        Number(req.body.duration) || 30;
    }

    if (
      req.body.instructions !==
      undefined
    ) {
      exam.instructions =
        cleanString(
          req.body.instructions
        );
    }

    if (
      req.body.status !==
      undefined
    ) {
      exam.status =
        cleanString(
          req.body.status
        );
    }

    exam.updatedAt = now();

    writeJSON(
      FILES.exams,
      db.exams
    );

    res.json({
      ok: true,
      message:
        "Exam updated.",
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
  requireSchoolUser,
  (req, res) => {
    const db = loadDB();

    let questions =
      db.questions.filter(
        (question) =>
          question.schoolId ===
          req.user.schoolId
      );

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

app.post(
  "/api/questions",
  requireAuth,
  requireRole(
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    const db = loadDB();

    const examId =
      cleanString(
        req.body.examId
      );

    const question =
      cleanString(
        req.body.question
      );

    if (!examId || !question) {
      return res.status(400).json({
        ok: false,
        message:
          "Exam ID and question are required."
      });
    }

    const exam =
      db.exams.find(
        (item) =>
          item.id === examId &&
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

    let options =
      req.body.options || [];

    if (!Array.isArray(options)) {
      options = [];
    }

    const newQuestion = {
      id: createId("question"),
      schoolId: req.user.schoolId,
      examId,
      question,
      options,
      answer:
        Number.isFinite(
          Number(req.body.answer)
        )
          ? Number(req.body.answer)
          : 0,
      points:
        Number(req.body.points) || 1,
      difficulty:
        cleanString(
          req.body.difficulty
        ) || "medium",
      tags:
        cleanString(
          req.body.tags
        ),
      createdBy: req.user.id,
      createdAt: now(),
      updatedAt: now()
    };

    db.questions.push(newQuestion);

    writeJSON(
      FILES.questions,
      db.questions
    );

    res.status(201).json({
      ok: true,
      message:
        "Question added successfully.",
      question: newQuestion
    });
  }
);

/* =========================================================
   START EXAM
========================================================= */

app.get(
  "/api/exams/:id/start",
  requireAuth,
  requireRole("student"),
  (req, res) => {
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
      ok: true,
      exam: {
        id: exam.id,
        title: exam.title,
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
  requireRole("student"),
  (req, res) => {
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

    for (const question of questions) {
      const points =
        Number(question.points) || 1;

      total += points;

      const selected =
        answers[question.id];

      const correct =
        Number(selected) ===
        Number(question.answer);

      if (correct) {
        score += points;
      }

      details.push({
        questionId:
          question.id,
        selected:
          selected !== undefined
            ? selected
            : null,
        correct
      });
    }

    const percentage =
      total > 0
        ? Number(
            ((score / total) * 100).toFixed(2)
          )
        : 0;

    const result = {
      id: createId("result"),
      schoolId: req.user.schoolId,
      examId: exam.id,
      studentId: req.user.id,
      score,
      total,
      percentage,
      details,
      submittedAt: now()
    };

    db.results.push(result);

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
  requireSchoolUser,
  (req, res) => {
    const db = loadDB();

    let results =
      db.results.filter(
        (result) =>
          result.schoolId ===
          req.user.schoolId
      );

    if (req.user.role === "student") {
      results =
        results.filter(
          (result) =>
            result.studentId ===
            req.user.id
        );
    }

    if (
      req.query.studentId &&
      req.user.role !== "student"
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
  requireSchoolUser,
  (req, res) => {
    const db = loadDB();

    const announcements =
      db.announcements
        .filter(
          (item) =>
            item.schoolId ===
            req.user.schoolId
        )
        .sort(
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

app.post(
  "/api/announcements",
  requireAuth,
  requireRole(
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    const db = loadDB();

    const title =
      cleanString(req.body.title);

    const message =
      cleanString(req.body.message);

    if (!title || !message) {
      return res.status(400).json({
        ok: false,
        message:
          "Title and message are required."
      });
    }

    const announcement = {
      id: createId("announcement"),
      schoolId: req.user.schoolId,
      title,
      message,
      createdBy: req.user.id,
      createdAt: now(),
      updatedAt: now()
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
  (req, res) => {
    const db = loadDB();

    let schoolId =
      req.user.schoolId;

    if (
      req.user.role === "superadmin" &&
      req.query.schoolId
    ) {
      schoolId =
        req.query.schoolId;
    }

    const users =
      db.users.filter(
        (user) =>
          user.schoolId === schoolId
      );

    const subjects =
      db.subjects.filter(
        (item) =>
          item.schoolId === schoolId
      );

    const exams =
      db.exams.filter(
        (item) =>
          item.schoolId === schoolId
      );

    const questions =
      db.questions.filter(
        (item) =>
          item.schoolId === schoolId
      );

    const results =
      db.results.filter(
        (item) =>
          item.schoolId === schoolId
      );

    const announcements =
      db.announcements.filter(
        (item) =>
          item.schoolId === schoolId
      );

    res.json({
      ok: true,
      summary: {
        users: users.length,
        teachers:
          users.filter(
            (user) =>
              user.role === "teacher"
          ).length,
        students:
          users.filter(
            (user) =>
              user.role === "student"
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
  requireRole("teacher"),
  (req, res) => {
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
        exams: exams.length,
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
  requireRole("student"),
  (req, res) => {
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
   SUPERADMIN - ALL SCHOOLS
========================================================= */

app.get(
  "/api/admin/schools",
  requireAuth,
  requireRole("superadmin"),
  (req, res) => {
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
            teacherCount:
              users.filter(
                (user) =>
                  user.role === "teacher"
              ).length,
            studentCount:
              users.filter(
                (user) =>
                  user.role === "student"
              ).length,
            adminCount:
              users.filter(
                (user) =>
                  user.role ===
                  "school_admin"
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
  requireRole("superadmin"),
  async (req, res) => {
    try {
      const db = loadDB();

      const name =
        cleanString(req.body.name);

      const motto =
        cleanString(req.body.motto);

      const adminName =
        cleanString(
          req.body.adminName
        );

      const adminUsername =
        cleanString(
          req.body.adminUsername
        ).toLowerCase();

      const adminEmail =
        cleanString(
          req.body.adminEmail
        ).toLowerCase();

      const adminPassword =
        cleanString(
          req.body.adminPassword
        );

      if (
        !name ||
        !adminName ||
        !adminUsername ||
        !adminEmail ||
        !adminPassword
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "School and administrator details are required."
        });
      }

      if (adminPassword.length < 6) {
        return res.status(400).json({
          ok: false,
          message:
            "Administrator password must contain at least 6 characters."
        });
      }

      if (
        db.users.some(
          (user) =>
            user.email === adminEmail
        )
      ) {
        return res.status(409).json({
          ok: false,
          message:
            "Administrator email already exists."
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
            "Administrator username already exists."
        });
      }

      const school = {
        id: createId("school"),
        name,
        motto,
        logo:
          cleanString(
            req.body.logo
          ),
        primaryColor:
          cleanString(
            req.body.primaryColor
          ) || "#2563eb",
        secondaryColor:
          cleanString(
            req.body.secondaryColor
          ) || "#16a34a",
        theme:
          cleanString(
            req.body.theme
          ) || "light",
        active: true,
        createdAt: now(),
        updatedAt: now()
      };

      const passwordHash =
        await bcrypt.hash(
          adminPassword,
          12
        );

      const admin = {
        id: createId("user"),
        fullName: adminName,
        username:
          adminUsername,
        email:
          adminEmail,
        passwordHash,
        role: "school_admin",
        schoolId:
          school.id,
        profilePicture: "",
        provider: "local",
        active: true,
        createdAt: now(),
        updatedAt: now()
      };

      db.schools.push(school);
      db.users.push(admin);

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
        "SUPERADMIN CREATE SCHOOL ERROR:",
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
  requireRole("superadmin"),
  (req, res) => {
    const db = loadDB();

    const school =
      getSchool(
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

    if (req.body.name !== undefined) {
      school.name =
        cleanString(
          req.body.name
        );
    }

    if (req.body.motto !== undefined) {
      school.motto =
        cleanString(
          req.body.motto
        );
    }

    if (req.body.logo !== undefined) {
      school.logo =
        cleanString(
          req.body.logo
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

    if (req.body.theme !== undefined) {
      school.theme =
        cleanString(
          req.body.theme
        );
    }

    if (req.body.active !== undefined) {
      school.active =
        Boolean(req.body.active);
    }

    school.updatedAt = now();

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
  requireRole("superadmin"),
  (req, res) => {
    const db = loadDB();

    const users =
      db.users.map(
        (user) => {
          const school =
            user.schoolId
              ? getSchool(
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
   SUPERADMIN - SUMMARY
========================================================= */

app.get(
  "/api/admin/platform-summary",
  requireAuth,
  requireRole("superadmin"),
  (req, res) => {
    const db = loadDB();

    res.json({
      ok: true,
      summary: {
        schools:
          db.schools.length,

        activeSchools:
          db.schools.filter(
            (school) =>
              school.active !== false
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
              user.role === "teacher"
          ).length,

        students:
          db.users.filter(
            (user) =>
              user.role === "student"
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
   SUPERADMIN - PLATFORM SETTINGS
========================================================= */

app.put(
  "/api/admin/settings",
  requireAuth,
  requireRole("superadmin"),
  (req, res) => {
    const db = loadDB();

    const settings = {
      ...db.settings
    };

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
        cleanString(
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
   DASHBOARD ROUTE
========================================================= */

app.get(
  "/dashboard",
  (req, res) => {
    if (!req.user) {
      return res.redirect(
        "/login.html"
      );
    }

    res.redirect(
      roleRedirect(req.user)
    );
  }
);

/* =========================================================
   STATIC FILES
========================================================= */

app.use(
  express.static(PUBLIC_DIR, {
    extensions: ["html"]
  })
);

/* =========================================================
   ROOT
========================================================= */

app.get("/", (req, res) => {
  const indexPath =
    path.join(
      PUBLIC_DIR,
      "index.html"
    );

  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }

  res.send(`
    <!doctype html>
    <html>
    <head>
      <title>SchoolHub Pro</title>
      <meta charset="utf-8">
      <style>
        body {
          margin: 0;
          min-height: 100vh;
          display: grid;
          place-items: center;
          font-family: Arial, sans-serif;
          background: #f4f7fb;
        }

        .box {
          background: white;
          padding: 40px;
          border-radius: 20px;
          text-align: center;
          box-shadow: 0 20px 60px rgba(0,0,0,.08);
        }

        a {
          color: #2563eb;
          text-decoration: none;
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
});

/* =========================================================
   UNKNOWN API ROUTES
========================================================= */

app.use("/api", (req, res) => {
  res.status(404).json({
    ok: false,
    message:
      "API endpoint not found."
  });
});

/* =========================================================
   ERROR HANDLER
========================================================= */

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
      message:
        "Internal server error."
    });
  }
);

/* =========================================================
   START SERVER
========================================================= */

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
          "================================================="
        );
        console.log(
          " SCHOOLHUB PRO IS ONLINE"
        );
        console.log(
          "================================================="
        );
        console.log(
          `Local: http://localhost:${PORT}`
        );
        console.log(
          `Health: http://localhost:${PORT}/api/health`
        );
        console.log(
          `Google Callback: ${GOOGLE_CALLBACK_URL}`
        );
        console.log(
          `Google Auth: ${
            googleConfigured
              ? "CONFIGURED"
              : "NOT CONFIGURED"
          }`
        );
        console.log(
          `Storage: ${STORAGE_ROOT}`
        );
        console.log(
          "================================================="
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

function shutdown(signal) {
  console.log(
    `\nReceived ${signal}. Shutting down...`
  );

  if (!server) {
    process.exit(0);
  }

  server.close(() => {
    console.log(
      "SchoolHub Pro server stopped."
    );

    process.exit(0);
  });

  setTimeout(() => {
    console.log(
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

/* =========================================================
   START
========================================================= */

startServer();
