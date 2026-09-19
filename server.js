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

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";

const PUBLIC_DIR = path.join(__dirname, "public");
const STORAGE_ROOT = process.env.STORAGE_ROOT || path.join(__dirname, "storage");
const DATA_DIR = path.join(STORAGE_ROOT, "data");

const USERS_FILE = path.join(DATA_DIR, "users.json");
const SCHOOLS_FILE = path.join(DATA_DIR, "schools.json");
const SETTINGS_FILE = path.join(DATA_DIR, "settings.json");

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_CALLBACK_URL =
  process.env.GOOGLE_CALLBACK_URL ||
  "http://localhost:3000/auth/google/callback";

const isProduction = process.env.NODE_ENV === "production";


// ============================================================
// DIRECTORIES
// ============================================================

for (const directory of [PUBLIC_DIR, STORAGE_ROOT, DATA_DIR]) {
  if (!fs.existsSync(directory)) {
    fs.mkdirSync(directory, { recursive: true });
  }
}


// ============================================================
// JSON DATABASE
// ============================================================

function ensureJsonFile(file, defaultValue) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify(defaultValue, null, 2));
  }
}

ensureJsonFile(USERS_FILE, []);
ensureJsonFile(SCHOOLS_FILE, []);
ensureJsonFile(SETTINGS_FILE, {
  platformName: "SchoolHub Pro",
  platformDescription: "Smart school management for modern schools.",
  defaultTheme: "light",
  maintenanceMode: false
});

function readJson(file, fallback) {
  try {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(file, JSON.stringify(fallback, null, 2));
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
  const tempFile = `${file}.tmp`;

  fs.writeFileSync(
    tempFile,
    JSON.stringify(data, null, 2),
    "utf8"
  );

  fs.renameSync(tempFile, file);
}

function getUsers() {
  return readJson(USERS_FILE, []);
}

function saveUsers(users) {
  writeJson(USERS_FILE, users);
}

function getSchools() {
  return readJson(SCHOOLS_FILE, []);
}

function saveSchools(schools) {
  writeJson(SCHOOLS_FILE, schools);
}

function getSettings() {
  return readJson(SETTINGS_FILE, {
    platformName: "SchoolHub Pro",
    platformDescription: "Smart school management for modern schools.",
    defaultTheme: "light",
    maintenanceMode: false
  });
}


// ============================================================
// HELPERS
// ============================================================

function uid(prefix = "id") {
  return `${prefix}_${Date.now()}_${Math.random()
    .toString(36)
    .slice(2, 10)}`;
}

function now() {
  return new Date().toISOString();
}

function clean(value) {
  return String(value || "").trim();
}

function normalizeEmail(value) {
  return clean(value).toLowerCase();
}

function normalizeUsername(value) {
  return clean(value).toLowerCase();
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
    active: user.active !== false,
    provider: user.provider || "local",
    createdAt: user.createdAt || null
  };
}

function findUserById(id) {
  return getUsers().find(user => user.id === id);
}

function findUserByEmail(email) {
  const normalized = normalizeEmail(email);

  return getUsers().find(
    user => normalizeEmail(user.email) === normalized
  );
}

function findUserByUsername(username) {
  const normalized = normalizeUsername(username);

  return getUsers().find(
    user => normalizeUsername(user.username) === normalized
  );
}

function findSchoolById(id) {
  return getSchools().find(school => school.id === id);
}

function rolePage(role) {
  switch (role) {
    case "superadmin":
      return "/admin.html";

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

function createSchool({
  name,
  motto = "",
  ownerName = "",
  ownerEmail = ""
}) {
  const schools = getSchools();

  const school = {
    id: uid("school"),
    name: clean(name),
    motto: clean(motto),
    logo: "",
    primaryColor: "#2563eb",
    secondaryColor: "#16a34a",
    theme: "light",
    active: true,
    createdAt: now(),
    ownerName: clean(ownerName),
    ownerEmail: normalizeEmail(ownerEmail)
  };

  schools.push(school);
  saveSchools(schools);

  return school;
}


// ============================================================
// EXPRESS
// ============================================================

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

app.set("trust proxy", 1);


// ============================================================
// SESSION
// ============================================================

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "CHANGE_THIS_SESSION_SECRET_IN_RAILWAY",

    resave: false,
    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      secure: isProduction,
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
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

passport.deserializeUser((id, done) => {
  try {
    const user = findUserById(id);

    if (!user) {
      return done(null, false);
    }

    done(null, user);
  } catch (error) {
    done(error);
  }
});


// ============================================================
// GOOGLE OAUTH
// ============================================================

const googleConfigured =
  Boolean(GOOGLE_CLIENT_ID) &&
  Boolean(GOOGLE_CLIENT_SECRET) &&
  Boolean(GOOGLE_CALLBACK_URL);

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

          const googleEmail =
            profile.emails &&
            profile.emails[0] &&
            profile.emails[0].value
              ? normalizeEmail(profile.emails[0].value)
              : "";

          const profilePicture =
            profile.photos &&
            profile.photos[0] &&
            profile.photos[0].value
              ? profile.photos[0].value
              : "";

          let user = users.find(
            item => item.googleId === googleId
          );

          // ----------------------------------------------------
          // Match existing account by verified email
          // ----------------------------------------------------

          if (!user && googleEmail) {
            user = users.find(
              item =>
                normalizeEmail(item.email) === googleEmail
            );

            if (user) {
              user.googleId = googleId;
              user.provider = "google";

              if (profilePicture) {
                user.profilePicture = profilePicture;
              }

              user.updatedAt = now();

              saveUsers(users);
            }
          }

          // ----------------------------------------------------
          // IMPORTANT:
          // Do not automatically create a new school account.
          // User must register through SchoolHub first.
          // ----------------------------------------------------

          if (!user) {
            return done(null, false, {
              message:
                "No SchoolHub account was found for this Google account. Register first, then use Google Sign-In."
            });
          }

          if (user.active === false) {
            return done(null, false, {
              message:
                "This SchoolHub account has been disabled."
            });
          }

          if (!user.email) {
            return done(null, false, {
              message:
                "Your Google account does not have an email address available."
            });
          }

          done(null, user);
        } catch (error) {
          console.error("GOOGLE STRATEGY ERROR:", error);
          done(error);
        }
      }
    )
  );
}


// ============================================================
// MIDDLEWARE
// ============================================================

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      ok: false,
      message: "Authentication required."
    });
  }

  const user = findUserById(req.session.userId);

  if (!user) {
    req.session.destroy(() => {});

    return res.status(401).json({
      ok: false,
      message: "Your session is no longer valid."
    });
  }

  if (user.active === false) {
    req.session.destroy(() => {});

    return res.status(403).json({
      ok: false,
      message: "Your account is disabled."
    });
  }

  req.currentUser = user;
  next();
}

function requireRoles(...roles) {
  return (req, res, next) => {
    if (!req.currentUser) {
      return res.status(401).json({
        ok: false,
        message: "Authentication required."
      });
    }

    if (!roles.includes(req.currentUser.role)) {
      return res.status(403).json({
        ok: false,
        message: "You do not have permission to access this resource."
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
    version: "4.1.0",
    environment: process.env.NODE_ENV || "development",
    port: PORT,
    storage: STORAGE_ROOT,
    googleAuth: googleConfigured
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
    settings: getSettings(),
    googleAuth: googleConfigured
  });
});

app.get("/api/platform-config", (req, res) => {
  res.json({
    ok: true,
    platformName: getSettings().platformName,
    platformDescription: getSettings().platformDescription,
    googleAuth: googleConfigured
  });
});


// ============================================================
// CURRENT USER
// ============================================================

app.get("/api/me", (req, res) => {
  if (!req.session.userId) {
    return res.json({
      ok: true,
      authenticated: false,
      user: null
    });
  }

  const user = findUserById(req.session.userId);

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
    user: safeUser(user),
    redirect: rolePage(user.role)
  });
});


// ============================================================
// REGISTER
// ============================================================

app.post("/api/register", async (req, res) => {
  try {
    const schoolName = clean(
      req.body.schoolName || req.body.name
    );

    const motto = clean(req.body.motto);

    const fullName = clean(req.body.fullName);

    const username = normalizeUsername(
      req.body.username
    );

    const email = normalizeEmail(req.body.email);

    const password = String(req.body.password || "");

    // --------------------------------------------------------
    // Validation
    // --------------------------------------------------------

    if (!schoolName) {
      return res.status(400).json({
        ok: false,
        message: "School name is required."
      });
    }

    if (!fullName) {
      return res.status(400).json({
        ok: false,
        message: "Full name is required."
      });
    }

    if (!username) {
      return res.status(400).json({
        ok: false,
        message: "Username is required."
      });
    }

    if (!email) {
      return res.status(400).json({
        ok: false,
        message: "Email is required."
      });
    }

    if (!email.includes("@")) {
      return res.status(400).json({
        ok: false,
        message: "Enter a valid email address."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        ok: false,
        message:
          "Password must contain at least 8 characters."
      });
    }

    // --------------------------------------------------------
    // Duplicate check
    // --------------------------------------------------------

    if (findUserByEmail(email)) {
      return res.status(409).json({
        ok: false,
        message:
          "An account with this email already exists."
      });
    }

    if (findUserByUsername(username)) {
      return res.status(409).json({
        ok: false,
        message:
          "That username is already in use."
      });
    }

    // --------------------------------------------------------
    // Create school
    // --------------------------------------------------------

    const school = createSchool({
      name: schoolName,
      motto,
      ownerName: fullName,
      ownerEmail: email
    });

    // --------------------------------------------------------
    // Hash password
    // --------------------------------------------------------

    const passwordHash = await bcrypt.hash(
      password,
      12
    );

    // --------------------------------------------------------
    // Create school admin
    // --------------------------------------------------------

    const user = {
      id: uid("user"),

      fullName,

      username,

      email,

      passwordHash,

      role: "school_admin",

      schoolId: school.id,

      googleId: "",

      provider: "local",

      profilePicture: "",

      active: true,

      createdAt: now(),

      updatedAt: now()
    };

    const users = getUsers();

    users.push(user);

    saveUsers(users);

    // --------------------------------------------------------
    // Login immediately
    // --------------------------------------------------------

    req.session.regenerate(error => {
      if (error) {
        console.error(
          "SESSION REGENERATE ERROR:",
          error
        );

        return res.status(500).json({
          ok: false,
          message:
            "Account was created, but automatic login failed. Please login manually."
        });
      }

      req.session.userId = user.id;

      req.session.save(saveError => {
        if (saveError) {
          console.error(
            "SESSION SAVE ERROR:",
            saveError
          );

          return res.status(500).json({
            ok: false,
            message:
              "Account was created, but automatic login failed. Please login manually."
          });
        }

        return res.status(201).json({
          ok: true,
          message:
            "School account created successfully.",
          user: safeUser(user),
          school,
          redirect: "/admin.html"
        });
      });
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      ok: false,
      message:
        "Unable to create the account right now."
    });
  }
});


// ============================================================
// LOGIN
// ============================================================

app.post("/api/login", async (req, res) => {
  try {
    const identifier = clean(
      req.body.identifier ||
      req.body.email ||
      req.body.username
    );

    const password = String(
      req.body.password || ""
    );

    if (!identifier || !password) {
      return res.status(400).json({
        ok: false,
        message:
          "Enter your username/email and password."
      });
    }

    const users = getUsers();

    const normalizedIdentifier =
      identifier.toLowerCase();

    const user = users.find(item => {
      return (
        normalizeEmail(item.email) ===
          normalizedIdentifier ||
        normalizeUsername(item.username) ===
          normalizedIdentifier
      );
    });

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
          "This account does not have a local password. Use Google Sign-In or contact your school administrator."
      });
    }

    const passwordCorrect =
      await bcrypt.compare(
        password,
        user.passwordHash
      );

    if (!passwordCorrect) {
      return res.status(401).json({
        ok: false,
        message:
          "Invalid username/email or password."
      });
    }

    req.session.regenerate(error => {
      if (error) {
        console.error(
          "LOGIN SESSION ERROR:",
          error
        );

        return res.status(500).json({
          ok: false,
          message:
            "Unable to create your login session."
        });
      }

      req.session.userId = user.id;

      req.session.save(saveError => {
        if (saveError) {
          console.error(
            "LOGIN SESSION SAVE ERROR:",
            saveError
          );

          return res.status(500).json({
            ok: false,
            message:
              "Unable to save your login session."
          });
        }

        return res.json({
          ok: true,
          message: "Login successful.",
          user: safeUser(user),
          redirect: rolePage(user.role)
        });
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


// ============================================================
// LOGOUT
// ============================================================

app.post("/api/logout", (req, res) => {
  req.logout(() => {
    req.session.destroy(error => {
      if (error) {
        console.error(
          "LOGOUT ERROR:",
          error
        );
      }

      res.clearCookie("connect.sid");

      res.json({
        ok: true,
        message: "Logged out successfully."
      });
    });
  });
});


// ============================================================
// GOOGLE LOGIN
// ============================================================

app.get("/auth/google", (req, res, next) => {
  if (!googleConfigured) {
    return res.status(503).send(`
      <html>
        <head>
          <title>Google Sign-In Not Configured</title>
          <style>
            body {
              font-family: Arial, sans-serif;
              background: #f5f7fb;
              display: flex;
              align-items: center;
              justify-content: center;
              min-height: 100vh;
              margin: 0;
            }
            .box {
              background: white;
              padding: 40px;
              max-width: 520px;
              border-radius: 18px;
              box-shadow: 0 15px 50px rgba(0,0,0,.08);
            }
            h1 { margin-top: 0; }
            a {
              display: inline-block;
              margin-top: 20px;
              text-decoration: none;
              color: #2563eb;
            }
          </style>
        </head>
        <body>
          <div class="box">
            <h1>Google Sign-In is not configured</h1>
            <p>
              Add GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
              and GOOGLE_CALLBACK_URL to your Railway variables.
            </p>
            <a href="/login.html">Return to login</a>
          </div>
        </body>
      </html>
    `);
  }

  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account"
  })(req, res, next);
});

app.get(
  "/auth/google/callback",

  (req, res, next) => {
    if (!googleConfigured) {
      return res.redirect(
        "/login.html?error=Google%20Sign-In%20is%20not%20configured"
      );
    }

    next();
  },

  passport.authenticate("google", {
    failureRedirect:
      "/login.html?error=Google%20Sign-In%20failed"
  }),

  (req, res) => {
    const user = req.user;

    if (!user) {
      return res.redirect(
        "/login.html?error=Google%20authentication%20failed"
      );
    }

    if (user.active === false) {
      req.logout(() => {
        res.redirect(
          "/login.html?error=Your%20account%20is%20disabled"
        );
      });

      return;
    }

    req.session.regenerate(error => {
      if (error) {
        console.error(
          "GOOGLE SESSION ERROR:",
          error
        );

        return res.redirect(
          "/login.html?error=Unable%20to%20create%20login%20session"
        );
      }

      req.session.userId = user.id;

      req.session.save(saveError => {
        if (saveError) {
          console.error(
            "GOOGLE SESSION SAVE ERROR:",
            saveError
          );

          return res.redirect(
            "/login.html?error=Unable%20to%20save%20login%20session"
          );
        }

        res.redirect(rolePage(user.role));
      });
    });
  }
);


// ============================================================
// SCHOOL
// ============================================================

app.get(
  "/api/school",
  requireLogin,
  (req, res) => {
    if (!req.currentUser.schoolId) {
      return res.json({
        ok: true,
        school: null
      });
    }

    const school = findSchoolById(
      req.currentUser.schoolId
    );

    res.json({
      ok: true,
      school: school || null
    });
  }
);


// ============================================================
// SCHOOL BRANDING
// ============================================================

app.put(
  "/api/school/branding",
  requireLogin,
  requireRoles("school_admin"),
  (req, res) => {
    const schoolId =
      req.currentUser.schoolId;

    const schools = getSchools();

    const school = schools.find(
      item => item.id === schoolId
    );

    if (!school) {
      return res.status(404).json({
        ok: false,
        message: "School not found."
      });
    }

    if (req.body.name !== undefined) {
      school.name = clean(req.body.name);
    }

    if (req.body.motto !== undefined) {
      school.motto = clean(req.body.motto);
    }

    if (req.body.primaryColor !== undefined) {
      school.primaryColor =
        clean(req.body.primaryColor) ||
        "#2563eb";
    }

    if (req.body.secondaryColor !== undefined) {
      school.secondaryColor =
        clean(req.body.secondaryColor) ||
        "#16a34a";
    }

    if (req.body.theme !== undefined) {
      const theme = clean(req.body.theme);

      if (
        ["light", "dark", "system"].includes(theme)
      ) {
        school.theme = theme;
      }
    }

    school.updatedAt = now();

    saveSchools(schools);

    res.json({
      ok: true,
      message: "School branding updated.",
      school
    });
  }
);


// ============================================================
// USERS - SCHOOL ADMIN
// ============================================================

app.get(
  "/api/users",
  requireLogin,
  requireRoles("school_admin", "superadmin"),
  (req, res) => {
    const users = getUsers();

    let visibleUsers;

    if (req.currentUser.role === "superadmin") {
      visibleUsers = users;
    } else {
      visibleUsers = users.filter(
        user =>
          user.schoolId ===
          req.currentUser.schoolId
      );
    }

    res.json({
      ok: true,
      users: visibleUsers.map(safeUser)
    });
  }
);


// ============================================================
// ADMIN SUMMARY
// ============================================================

app.get(
  "/api/admin/summary",
  requireLogin,
  requireRoles("school_admin", "superadmin"),
  (req, res) => {
    const users = getUsers();
    const schools = getSchools();

    let schoolUsers;

    if (req.currentUser.role === "superadmin") {
      schoolUsers = users;
    } else {
      schoolUsers = users.filter(
        user =>
          user.schoolId ===
          req.currentUser.schoolId
      );
    }

    res.json({
      ok: true,
      summary: {
        totalSchools:
          req.currentUser.role === "superadmin"
            ? schools.length
            : 1,

        totalUsers: schoolUsers.length,

        totalAdmins: schoolUsers.filter(
          user =>
            user.role ===
            "school_admin"
        ).length,

        totalTeachers: schoolUsers.filter(
          user =>
            user.role === "teacher"
        ).length,

        totalStudents: schoolUsers.filter(
          user =>
            user.role === "student"
        ).length
      }
    });
  }
);


// ============================================================
// SUPERADMIN
// ============================================================

app.get(
  "/api/admin/schools",
  requireLogin,
  requireRoles("superadmin"),
  (req, res) => {
    res.json({
      ok: true,
      schools: getSchools()
    });
  }
);

app.get(
  "/api/admin/users",
  requireLogin,
  requireRoles("superadmin"),
  (req, res) => {
    res.json({
      ok: true,
      users: getUsers().map(safeUser)
    });
  }
);


// ============================================================
// PROFILE
// ============================================================

app.get(
  "/api/profile",
  requireLogin,
  (req, res) => {
    res.json({
      ok: true,
      user: safeUser(req.currentUser)
    });
  }
);


// ============================================================
// TEACHER SUMMARY
// ============================================================

app.get(
  "/api/teacher/summary",
  requireLogin,
  requireRoles("teacher"),
  (req, res) => {
    const schoolId =
      req.currentUser.schoolId;

    const users = getUsers();

    const schoolStudents =
      users.filter(
        user =>
          user.schoolId === schoolId &&
          user.role === "student"
      );

    res.json({
      ok: true,
      summary: {
        students: schoolStudents.length,
        exams: 0,
        questions: 0,
        results: 0
      }
    });
  }
);


// ============================================================
// STUDENT SUMMARY
// ============================================================

app.get(
  "/api/student/summary",
  requireLogin,
  requireRoles("student"),
  (req, res) => {
    res.json({
      ok: true,
      summary: {
        availableExams: 0,
        completedExams: 0,
        averageScore: 0,
        announcements: 0
      }
    });
  }
);


// ============================================================
// PROTECT UNKNOWN API ROUTES
// ============================================================

app.use("/api", (req, res) => {
  res.status(404).json({
    ok: false,
    message: "API route not found."
  });
});


// ============================================================
// FRONTEND
// ============================================================

app.use(express.static(PUBLIC_DIR));

app.get("*", (req, res) => {
  if (
    req.path.startsWith("/api/") ||
    req.path.startsWith("/auth/")
  ) {
    return res.status(404).send("Not found");
  }

  const indexFile =
    path.join(PUBLIC_DIR, "index.html");

  if (fs.existsSync(indexFile)) {
    return res.sendFile(indexFile);
  }

  res.status(404).send(
    "SchoolHub Pro frontend is not installed."
  );
});


// ============================================================
// ERROR HANDLER
// ============================================================

app.use((error, req, res, next) => {
  console.error("SERVER ERROR:", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    ok: false,
    message: "Internal server error."
  });
});


// ============================================================
// START SERVER
// ============================================================

const server = app.listen(
  PORT,
  HOST,
  () => {
    console.log("");
    console.log("========================================");
    console.log("       SCHOOLHUB PRO SERVER");
    console.log("========================================");
    console.log(`Port: ${PORT}`);
    console.log(
      `Environment: ${
        process.env.NODE_ENV || "development"
      }`
    );
    console.log(`Storage: ${STORAGE_ROOT}`);
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
      `Server listening on ${HOST}`
    );
    console.log("========================================");
    console.log("");
  }
);


// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

function shutdown(signal) {
  console.log(
    `${signal} received. Shutting down SchoolHub Pro...`
  );

  server.close(() => {
    console.log(
      "SchoolHub Pro server stopped."
    );

    process.exit(0);
  });

  setTimeout(() => {
    process.exit(1);
  }, 10000).unref();
}

process.on("SIGTERM", () => {
  shutdown("SIGTERM");
});

process.on("SIGINT", () => {
  shutdown("SIGINT");
});

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
