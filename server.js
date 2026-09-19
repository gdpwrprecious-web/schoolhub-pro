// ============================================================
// SCHOOLHUB PRO - MAIN SERVER
// Multi-School School Management + CBT Platform
// Login / Logout / Google Auth / Superadmin / School Admin
// Teacher / Student / JSON Storage / Railway Ready
// ============================================================

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const dotenv = require("dotenv");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

dotenv.config();

const app = express();

// ============================================================
// CONFIGURATION
// ============================================================

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";

const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PRODUCTION = NODE_ENV === "production";

const STORAGE_ROOT =
  process.env.STORAGE_ROOT ||
  path.join(__dirname, "storage");

const DATA_DIR = path.join(STORAGE_ROOT, "data");
const PUBLIC_DIR = path.join(__dirname, "public");

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "CHANGE_THIS_SESSION_SECRET_IN_PRODUCTION";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";

const GOOGLE_CALLBACK_URL =
  process.env.GOOGLE_CALLBACK_URL ||
  `http://localhost:${PORT}/auth/google/callback`;

const googleConfigured =
  Boolean(GOOGLE_CLIENT_ID) &&
  Boolean(GOOGLE_CLIENT_SECRET) &&
  Boolean(GOOGLE_CALLBACK_URL);

// Railway is behind a reverse proxy.
// This is important for secure session cookies.
if (IS_PRODUCTION) {
  app.set("trust proxy", 1);
}

// ============================================================
// CREATE DIRECTORIES
// ============================================================

if (!fs.existsSync(STORAGE_ROOT)) {
  fs.mkdirSync(STORAGE_ROOT, { recursive: true });
}

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

if (!fs.existsSync(PUBLIC_DIR)) {
  fs.mkdirSync(PUBLIC_DIR, { recursive: true });
}

// ============================================================
// JSON DATABASE
// ============================================================

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

const DEFAULT_SETTINGS = {
  platformName: "SchoolHub Pro",
  platformDescription:
    "Smart school management and CBT platform for modern schools.",
  defaultTheme: "light",
  maintenanceMode: false,
  primaryColor: "#2563eb",
  secondaryColor: "#16a34a"
};

// ============================================================
// DATABASE HELPERS
// ============================================================

function ensureJsonFile(file, defaultValue = []) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(
      file,
      JSON.stringify(defaultValue, null, 2),
      "utf8"
    );
  }
}

function readJson(file, fallback = []) {
  try {
    if (!fs.existsSync(file)) {
      ensureJsonFile(file, fallback);
      return fallback;
    }

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

ensureJsonFile(FILES.users, []);
ensureJsonFile(FILES.schools, []);
ensureJsonFile(FILES.settings, DEFAULT_SETTINGS);
ensureJsonFile(FILES.subjects, []);
ensureJsonFile(FILES.exams, []);
ensureJsonFile(FILES.questions, []);
ensureJsonFile(FILES.results, []);
ensureJsonFile(FILES.announcements, []);

// ============================================================
// ID / DATE HELPERS
// ============================================================

function createId(prefix = "id") {
  return `${prefix}_${crypto.randomUUID()}`;
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

// ============================================================
// DATABASE ACCESS
// ============================================================

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
  return {
    ...DEFAULT_SETTINGS,
    ...readJson(FILES.settings, DEFAULT_SETTINGS)
  };
}

function saveSettings(data) {
  writeJson(FILES.settings, {
    ...DEFAULT_SETTINGS,
    ...data
  });
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

// ============================================================
// SCHOOL HELPERS
// ============================================================

function getSchoolById(id) {
  return getSchools().find(
    school => String(school.id) === String(id)
  );
}

function getUserById(id) {
  return getUsers().find(
    user => String(user.id) === String(id)
  );
}

function getUserSchool(user) {
  if (!user || !user.schoolId) return null;
  return getSchoolById(user.schoolId);
}

function sameSchool(user, schoolId) {
  return (
    user &&
    user.role === "superadmin" ||
    Boolean(
      user &&
      user.schoolId &&
      String(user.schoolId) === String(schoolId)
    )
  );
}

// ============================================================
// SAFE USER
// ============================================================

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
    createdAt: user.createdAt || null,
    updatedAt: user.updatedAt || null
  };
}

// ============================================================
// ROLE REDIRECT
// ============================================================

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

// ============================================================
// EXPRESS MIDDLEWARE
// ============================================================

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// ============================================================
// SESSION
// ============================================================
//
// IMPORTANT:
// - trust proxy is enabled above for Railway
// - secure cookie is enabled only in production
// - sameSite=lax works with Google OAuth callback
// - session is explicitly saved before redirects
//

app.use(
  session({
    name: "schoolhub.sid",

    secret: SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    rolling: true,

    cookie: {
      httpOnly: true,

      secure: IS_PRODUCTION,

      sameSite: "lax",

      maxAge: 1000 * 60 * 60 * 24 * 7,

      path: "/"
    }
  })
);

// ============================================================
// PASSPORT
// ============================================================

app.use(passport.initialize());
app.use(passport.session());

// ============================================================
// PASSPORT SERIALIZATION
// ============================================================

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  try {
    const user = getUserById(id);

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
            profile.emails &&
            profile.emails[0] &&
            normalizeEmail(profile.emails[0].value);

          const existing =
            users.find(user => user.googleId === googleId) ||
            users.find(
              user =>
                email &&
                normalizeEmail(user.email) === email
            );

          // Google does NOT automatically create a school account.
          if (!existing) {
            return done(null, false, {
              message: "google_account_not_registered"
            });
          }

          if (existing.active === false) {
            return done(null, false, {
              message: "account_disabled"
            });
          }

          let changed = false;

          if (!existing.googleId) {
            existing.googleId = googleId;
            changed = true;
          }

          existing.provider = "google";
          existing.updatedAt = now();

          if (
            profile.photos &&
            profile.photos[0] &&
            !existing.profilePicture
          ) {
            existing.profilePicture =
              profile.photos[0].value;

            changed = true;
          }

          if (changed) {
            saveUsers(users);
          }

          return done(null, existing);
        } catch (error) {
          console.error("GOOGLE STRATEGY ERROR:", error);
          return done(error);
        }
      }
    )
  );
}

// ============================================================
// AUTH MIDDLEWARE
// ============================================================

function requireAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    if (req.user && req.user.active !== false) {
      return next();
    }
  }

  if (req.accepts("html")) {
    return res.redirect("/login.html");
  }

  return res.status(401).json({
    ok: false,
    error: "Authentication required"
  });
}

function requireRole(...roles) {
  return [
    requireAuth,
    (req, res, next) => {
      if (!req.user || !roles.includes(req.user.role)) {
        return res.status(403).json({
          ok: false,
          error: "Access denied"
        });
      }

      next();
    }
  ];
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
    environment: NODE_ENV,
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
    platform: getSettings()
  });
});

app.get("/api/platform-config", (req, res) => {
  const settings = getSettings();

  res.json({
    ok: true,
    platformName: settings.platformName,
    platformDescription: settings.platformDescription,
    defaultTheme: settings.defaultTheme,
    primaryColor: settings.primaryColor,
    secondaryColor: settings.secondaryColor
  });
});

// ============================================================
// CURRENT USER
// ============================================================

app.get("/api/me", (req, res) => {
  if (
    !req.isAuthenticated ||
    !req.isAuthenticated() ||
    !req.user
  ) {
    return res.status(401).json({
      ok: false,
      authenticated: false,
      user: null
    });
  }

  const user = getUserById(req.user.id);

  if (!user || user.active === false) {
    req.logout(() => {});

    return res.status(401).json({
      ok: false,
      authenticated: false,
      user: null
    });
  }

  res.json({
    ok: true,
    authenticated: true,
    user: safeUser(user),
    school: getUserSchool(user)
  });
});

// ============================================================
// REGISTER
// ============================================================

async function registerSchoolAdmin(req, res) {
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
        ok: false,
        error: "Please fill all required fields"
      });
    }

    if (String(password).length < 6) {
      return res.status(400).json({
        ok: false,
        error: "Password must contain at least 6 characters"
      });
    }

    const normalizedEmail = normalizeEmail(email);
    const normalizedUsername =
      normalizeUsername(username);

    const users = getUsers();

    if (
      users.some(
        user =>
          normalizeEmail(user.email) === normalizedEmail
      )
    ) {
      return res.status(409).json({
        ok: false,
        error: "Email already exists"
      });
    }

    if (
      users.some(
        user =>
          normalizeUsername(user.username) ===
          normalizedUsername
      )
    ) {
      return res.status(409).json({
        ok: false,
        error: "Username already exists"
      });
    }

    const schools = getSchools();

    const school = {
      id: createId("school"),
      name: clean(schoolName),
      motto: clean(motto),
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

    const passwordHash = await bcrypt.hash(
      String(password),
      12
    );

    const user = {
      id: createId("user"),
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

    // IMPORTANT:
    // Explicitly create and save session before redirect.
    req.login(user, error => {
      if (error) {
        console.error("REGISTER SESSION ERROR:", error);

        return res.status(500).json({
          ok: false,
          error: "Account created but session could not be created"
        });
      }

      req.session.save(saveError => {
        if (saveError) {
          console.error(
            "REGISTER SESSION SAVE ERROR:",
            saveError
          );

          return res.status(500).json({
            ok: false,
            error: "Account created but session could not be saved"
          });
        }

        return res.json({
          ok: true,
          message: "Account created successfully",
          user: safeUser(user),
          redirect: "/admin.html"
        });
      });
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "Registration failed"
    });
  }
}

app.post("/api/register", registerSchoolAdmin);

// Old frontend compatibility
app.post("/api/signup", registerSchoolAdmin);

// ============================================================
// LOGIN
// ============================================================

app.post("/api/login", async (req, res) => {
  try {
    const identifier = clean(req.body.identifier);
    const password = String(req.body.password || "");

    if (!identifier || !password) {
      return res.status(400).json({
        ok: false,
        error: "Username/email and password are required"
      });
    }

    const users = getUsers();

    const normalized = identifier.toLowerCase();

    const user = users.find(
      item =>
        normalizeEmail(item.email) === normalized ||
        normalizeUsername(item.username) === normalized
    );

    if (!user) {
      return res.status(401).json({
        ok: false,
        error: "Invalid username/email or password"
      });
    }

    if (user.active === false) {
      return res.status(403).json({
        ok: false,
        error: "This account has been disabled"
      });
    }

    if (!user.passwordHash) {
      return res.status(401).json({
        ok: false,
        error: "This account uses Google Sign-In"
      });
    }

    const validPassword = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!validPassword) {
      return res.status(401).json({
        ok: false,
        error: "Invalid username/email or password"
      });
    }

    // Clear any old session before creating the new login session.
    req.session.regenerate(regenerateError => {
      if (regenerateError) {
        console.error(
          "SESSION REGENERATE ERROR:",
          regenerateError
        );

        return res.status(500).json({
          ok: false,
          error: "Unable to create login session"
        });
      }

      req.login(user, loginError => {
        if (loginError) {
          console.error("LOGIN ERROR:", loginError);

          return res.status(500).json({
            ok: false,
            error: "Unable to create login session"
          });
        }

        user.updatedAt = now();

        const latestUsers = getUsers();
        const index = latestUsers.findIndex(
          item => item.id === user.id
        );

        if (index !== -1) {
          latestUsers[index] = user;
          saveUsers(latestUsers);
        }

        // CRITICAL FIX:
        // Save session completely BEFORE responding.
        req.session.save(saveError => {
          if (saveError) {
            console.error(
              "LOGIN SESSION SAVE ERROR:",
              saveError
            );

            return res.status(500).json({
              ok: false,
              error: "Login session could not be saved"
            });
          }

          return res.json({
            ok: true,
            message: "Login successful",
            user: safeUser(user),
            redirect: roleRedirect(user)
          });
        });
      });
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      ok: false,
      error: "An internal error occurred during login"
    });
  }
});

// ============================================================
// LOGOUT
// ============================================================

app.post("/api/logout", (req, res) => {
  if (!req.session) {
    return res.json({
      ok: true,
      redirect: "/login.html"
    });
  }

  req.logout(logoutError => {
    if (logoutError) {
      console.error("LOGOUT ERROR:", logoutError);

      return res.status(500).json({
        ok: false,
        error: "Logout failed"
      });
    }

    req.session.destroy(sessionError => {
      if (sessionError) {
        console.error(
          "SESSION DESTROY ERROR:",
          sessionError
        );

        return res.status(500).json({
          ok: false,
          error: "Session could not be destroyed"
        });
      }

      res.clearCookie("schoolhub.sid", {
        httpOnly: true,
        secure: IS_PRODUCTION,
        sameSite: "lax",
        path: "/"
      });

      return res.json({
        ok: true,
        message: "Logged out successfully",
        redirect: "/login.html"
      });
    });
  });
});

// Also support GET logout for old dashboard links.
app.get("/logout", (req, res) => {
  req.logout(() => {
    req.session.destroy(() => {
      res.clearCookie("schoolhub.sid", {
        httpOnly: true,
        secure: IS_PRODUCTION,
        sameSite: "lax",
        path: "/"
      });

      res.redirect("/login.html");
    });
  });
});

// ============================================================
// GOOGLE LOGIN
// ============================================================

app.get("/auth/google", (req, res, next) => {
  if (!googleConfigured) {
    return res.redirect(
      "/login.html?error=google_not_configured"
    );
  }

  passport.authenticate("google", {
    scope: ["profile", "email"],
    session: true
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
        session: true,
        failureRedirect:
          "/login.html?error=google_account_not_registered"
      },
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
            info && info.message
              ? info.message
              : "google_login_failed";

          return res.redirect(
            `/login.html?error=${encodeURIComponent(message)}`
          );
        }

        req.login(user, loginError => {
          if (loginError) {
            console.error(
              "GOOGLE SESSION ERROR:",
              loginError
            );

            return res.redirect(
              "/login.html?error=google_session_failed"
            );
          }

          // CRITICAL:
          // Google session must be saved before redirect.
          req.session.save(saveError => {
            if (saveError) {
              console.error(
                "GOOGLE SESSION SAVE ERROR:",
                saveError
              );

              return res.redirect(
                "/login.html?error=google_session_failed"
              );
            }

            return res.redirect(
              roleRedirect(user)
            );
          });
        });
      }
    )(req, res, next);
  }
);

// ============================================================
// SCHOOL
// ============================================================

app.get(
  "/api/school",
  ...requireRole(
    "superadmin",
    "school_admin",
    "teacher",
    "student"
  ),
  (req, res) => {
    if (req.user.role === "superadmin") {
      return res.json({
        ok: true,
        school: null
      });
    }

    const school = getUserSchool(req.user);

    if (!school) {
      return res.status(404).json({
        ok: false,
        error: "School not found"
      });
    }

    res.json({
      ok: true,
      school
    });
  }
);

// ============================================================
// SCHOOL BRANDING
// ============================================================

app.put(
  "/api/school/branding",
  ...requireRole("school_admin"),
  (req, res) => {
    const schools = getSchools();

    const index = schools.findIndex(
      school =>
        String(school.id) ===
        String(req.user.schoolId)
    );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error: "School not found"
      });
    }

    const school = schools[index];

    if (req.body.name !== undefined) {
      school.name = clean(req.body.name);
    }

    if (req.body.motto !== undefined) {
      school.motto = clean(req.body.motto);
    }

    if (req.body.logo !== undefined) {
      school.logo = clean(req.body.logo);
    }

    if (req.body.primaryColor !== undefined) {
      school.primaryColor =
        clean(req.body.primaryColor) || "#2563eb";
    }

    if (req.body.secondaryColor !== undefined) {
      school.secondaryColor =
        clean(req.body.secondaryColor) || "#16a34a";
    }

    if (req.body.theme !== undefined) {
      school.theme =
        clean(req.body.theme) || "light";
    }

    school.updatedAt = now();

    schools[index] = school;
    saveSchools(schools);

    res.json({
      ok: true,
      message: "School branding updated",
      school
    });
  }
);

// ============================================================
// USERS - SCHOOL ADMIN
// ============================================================

app.get(
  "/api/users",
  ...requireRole("school_admin", "superadmin"),
  (req, res) => {
    let users = getUsers();

    if (req.user.role !== "superadmin") {
      users = users.filter(
        user =>
          String(user.schoolId) ===
          String(req.user.schoolId)
      );
    }

    res.json({
      ok: true,
      users: users.map(safeUser)
    });
  }
);

// ============================================================
// CREATE USER
// ============================================================

app.post(
  "/api/users",
  ...requireRole("school_admin", "superadmin"),
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

      const allowedRoles = [
        "teacher",
        "student"
      ];

      if (
        !fullName ||
        !username ||
        !email ||
        !password ||
        !role
      ) {
        return res.status(400).json({
          ok: false,
          error: "All required fields must be provided"
        });
      }

      if (!allowedRoles.includes(role)) {
        return res.status(400).json({
          ok: false,
          error:
            "Only teacher and student accounts can be created here"
        });
      }

      const targetSchoolId =
        req.user.role === "superadmin"
          ? schoolId
          : req.user.schoolId;

      if (!targetSchoolId) {
        return res.status(400).json({
          ok: false,
          error: "School is required"
        });
      }

      const school = getSchoolById(targetSchoolId);

      if (!school) {
        return res.status(404).json({
          ok: false,
          error: "School not found"
        });
      }

      const users = getUsers();

      const normalizedEmail =
        normalizeEmail(email);

      const normalizedUsername =
        normalizeUsername(username);

      if (
        users.some(
          user =>
            normalizeEmail(user.email) ===
            normalizedEmail
        )
      ) {
        return res.status(409).json({
          ok: false,
          error: "Email already exists"
        });
      }

      if (
        users.some(
          user =>
            normalizeUsername(user.username) ===
            normalizedUsername
        )
      ) {
        return res.status(409).json({
          ok: false,
          error: "Username already exists"
        });
      }

      const passwordHash = await bcrypt.hash(
        String(password),
        12
      );

      const user = {
        id: createId("user"),
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
        message: "User created successfully",
        user: safeUser(user)
      });
    } catch (error) {
      console.error("CREATE USER ERROR:", error);

      res.status(500).json({
        ok: false,
        error: "Unable to create user"
      });
    }
  }
);

// ============================================================
// UPDATE USER
// ============================================================

app.put(
  "/api/users/:id",
  ...requireRole("school_admin", "superadmin"),
  async (req, res) => {
    try {
      const users = getUsers();

      const index = users.findIndex(
        user =>
          String(user.id) ===
          String(req.params.id)
      );

      if (index === -1) {
        return res.status(404).json({
          ok: false,
          error: "User not found"
        });
      }

      const user = users[index];

      if (
        req.user.role !== "superadmin" &&
        String(user.schoolId) !==
          String(req.user.schoolId)
      ) {
        return res.status(403).json({
          ok: false,
          error: "Access denied"
        });
      }

      if (req.body.fullName !== undefined) {
        user.fullName = clean(req.body.fullName);
      }

      if (req.body.username !== undefined) {
        user.username =
          normalizeUsername(req.body.username);
      }

      if (req.body.email !== undefined) {
        user.email =
          normalizeEmail(req.body.email);
      }

      if (
        req.body.role !== undefined &&
        ["school_admin", "teacher", "student", "superadmin"].includes(
          req.body.role
        )
      ) {
        if (
          req.user.role === "superadmin"
        ) {
          user.role = req.body.role;
        }
      }

      if (req.body.active !== undefined) {
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

      if (req.body.profilePicture !== undefined) {
        user.profilePicture =
          clean(req.body.profilePicture);
      }

      user.updatedAt = now();

      users[index] = user;
      saveUsers(users);

      res.json({
        ok: true,
        message: "User updated",
        user: safeUser(user)
      });
    } catch (error) {
      console.error("UPDATE USER ERROR:", error);

      res.status(500).json({
        ok: false,
        error: "Unable to update user"
      });
    }
  }
);

// ============================================================
// DELETE USER
// ============================================================

app.delete(
  "/api/users/:id",
  ...requireRole("school_admin", "superadmin"),
  (req, res) => {
    const users = getUsers();

    const index = users.findIndex(
      user =>
        String(user.id) ===
        String(req.params.id)
    );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error: "User not found"
      });
    }

    const user = users[index];

    if (
      req.user.role !== "superadmin" &&
      String(user.schoolId) !==
        String(req.user.schoolId)
    ) {
      return res.status(403).json({
        ok: false,
        error: "Access denied"
      });
    }

    if (user.id === req.user.id) {
      return res.status(400).json({
        ok: false,
        error: "You cannot delete your own account"
      });
    }

    users.splice(index, 1);
    saveUsers(users);

    res.json({
      ok: true,
      message: "User deleted"
    });
  }
);

// ============================================================
// PROFILE
// ============================================================

app.put(
  "/api/profile",
  ...requireRole(
    "superadmin",
    "school_admin",
    "teacher",
    "student"
  ),
  async (req, res) => {
    try {
      const users = getUsers();

      const index = users.findIndex(
        user => user.id === req.user.id
      );

      if (index === -1) {
        return res.status(404).json({
          ok: false,
          error: "User not found"
        });
      }

      const user = users[index];

      if (req.body.fullName !== undefined) {
        user.fullName = clean(req.body.fullName);
      }

      if (req.body.profilePicture !== undefined) {
        user.profilePicture =
          clean(req.body.profilePicture);
      }

      if (req.body.password) {
        user.passwordHash =
          await bcrypt.hash(
            String(req.body.password),
            12
          );
      }

      user.updatedAt = now();

      users[index] = user;
      saveUsers(users);

      req.user = user;

      res.json({
        ok: true,
        message: "Profile updated",
        user: safeUser(user)
      });
    } catch (error) {
      console.error("PROFILE ERROR:", error);

      res.status(500).json({
        ok: false,
        error: "Unable to update profile"
      });
    }
  }
);

// ============================================================
// SUBJECTS
// ============================================================

app.get(
  "/api/subjects",
  ...requireRole(
    "school_admin",
    "teacher",
    "student"
  ),
  (req, res) => {
    const subjects = getSubjects().filter(
      subject =>
        String(subject.schoolId) ===
        String(req.user.schoolId)
    );

    res.json({
      ok: true,
      subjects
    });
  }
);

app.post(
  "/api/subjects",
  ...requireRole("school_admin"),
  (req, res) => {
    const { name, code, description } =
      req.body;

    if (!name) {
      return res.status(400).json({
        ok: false,
        error: "Subject name is required"
      });
    }

    const subjects = getSubjects();

    const subject = {
      id: createId("subject"),
      schoolId: req.user.schoolId,
      name: clean(name),
      code: clean(code),
      description: clean(description),
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
  ...requireRole("school_admin"),
  (req, res) => {
    const subjects = getSubjects();

    const index = subjects.findIndex(
      subject =>
        String(subject.id) ===
          String(req.params.id) &&
        String(subject.schoolId) ===
          String(req.user.schoolId)
    );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error: "Subject not found"
      });
    }

    subjects.splice(index, 1);
    saveSubjects(subjects);

    res.json({
      ok: true,
      message: "Subject deleted"
    });
  }
);

// ============================================================
// EXAMS
// ============================================================

app.get(
  "/api/exams",
  ...requireRole(
    "school_admin",
    "teacher",
    "student"
  ),
  (req, res) => {
    const exams = getExams().filter(
      exam =>
        String(exam.schoolId) ===
        String(req.user.schoolId)
    );

    res.json({
      ok: true,
      exams
    });
  }
);

app.post(
  "/api/exams",
  ...requireRole("school_admin", "teacher"),
  (req, res) => {
    const {
      title,
      subjectId,
      description,
      duration,
      totalMarks,
      startTime,
      endTime,
      status
    } = req.body;

    if (!title || !subjectId) {
      return res.status(400).json({
        ok: false,
        error: "Title and subject are required"
      });
    }

    const subjects = getSubjects();

    const subject = subjects.find(
      item =>
        String(item.id) ===
          String(subjectId) &&
        String(item.schoolId) ===
          String(req.user.schoolId)
    );

    if (!subject) {
      return res.status(404).json({
        ok: false,
        error: "Subject not found"
      });
    }

    const exams = getExams();

    const exam = {
      id: createId("exam"),
      schoolId: req.user.schoolId,
      subjectId,
      title: clean(title),
      description: clean(description),
      duration: Number(duration || 30),
      totalMarks: Number(totalMarks || 0),
      startTime: startTime || null,
      endTime: endTime || null,
      status: clean(status) || "draft",
      createdBy: req.user.id,
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

app.put(
  "/api/exams/:id",
  ...requireRole("school_admin", "teacher"),
  (req, res) => {
    const exams = getExams();

    const index = exams.findIndex(
      exam =>
        String(exam.id) ===
          String(req.params.id) &&
        String(exam.schoolId) ===
          String(req.user.schoolId)
    );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error: "Exam not found"
      });
    }

    const exam = exams[index];

    if (req.body.title !== undefined) {
      exam.title = clean(req.body.title);
    }

    if (req.body.description !== undefined) {
      exam.description =
        clean(req.body.description);
    }

    if (req.body.duration !== undefined) {
      exam.duration =
        Number(req.body.duration);
    }

    if (req.body.totalMarks !== undefined) {
      exam.totalMarks =
        Number(req.body.totalMarks);
    }

    if (req.body.status !== undefined) {
      exam.status = clean(req.body.status);
    }

    if (req.body.startTime !== undefined) {
      exam.startTime = req.body.startTime;
    }

    if (req.body.endTime !== undefined) {
      exam.endTime = req.body.endTime;
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

// ============================================================
// QUESTIONS
// ============================================================

app.get(
  "/api/questions",
  ...requireRole(
    "school_admin",
    "teacher",
    "student"
  ),
  (req, res) => {
    let questions =
      getQuestions().filter(
        question =>
          String(question.schoolId) ===
          String(req.user.schoolId)
      );

    if (req.query.examId) {
      questions = questions.filter(
        question =>
          String(question.examId) ===
          String(req.query.examId)
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
  ...requireRole("school_admin", "teacher"),
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

    if (!examId || !question) {
      return res.status(400).json({
        ok: false,
        error: "Exam and question are required"
      });
    }

    const exams = getExams();

    const exam = exams.find(
      item =>
        String(item.id) ===
          String(examId) &&
        String(item.schoolId) ===
          String(req.user.schoolId)
    );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        error: "Exam not found"
      });
    }

    const questions = getQuestions();

    const newQuestion = {
      id: createId("question"),
      schoolId: req.user.schoolId,
      examId,
      question: clean(question),
      options: Array.isArray(options)
        ? options
        : [],
      answer:
        answer !== undefined
          ? Number(answer)
          : 0,
      points: Number(points || 1),
      difficulty:
        clean(difficulty) || "easy",
      tags: clean(tags),
      createdBy: req.user.id,
      createdAt: now(),
      updatedAt: now()
    };

    questions.push(newQuestion);
    saveQuestions(questions);

    res.status(201).json({
      ok: true,
      question: newQuestion
    });
  }
);

// ============================================================
// START EXAM
// ============================================================

app.post(
  "/api/exams/:id/start",
  ...requireRole("student"),
  (req, res) => {
    const exams = getExams();

    const exam = exams.find(
      item =>
        String(item.id) ===
          String(req.params.id) &&
        String(item.schoolId) ===
          String(req.user.schoolId)
    );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        error: "Exam not found"
      });
    }

    const questions =
      getQuestions().filter(
        question =>
          String(question.examId) ===
            String(exam.id) &&
          String(question.schoolId) ===
            String(req.user.schoolId)
      );

    const safeQuestions = questions.map(
      question => ({
        id: question.id,
        examId: question.examId,
        question: question.question,
        options: question.options,
        points: question.points,
        difficulty: question.difficulty,
        tags: question.tags
      })
    );

    res.json({
      ok: true,
      exam,
      questions: safeQuestions
    });
  }
);

// ============================================================
// SUBMIT EXAM
// ============================================================

app.post(
  "/api/exams/:id/submit",
  ...requireRole("student"),
  (req, res) => {
    const exams = getExams();

    const exam = exams.find(
      item =>
        String(item.id) ===
          String(req.params.id) &&
        String(item.schoolId) ===
          String(req.user.schoolId)
    );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        error: "Exam not found"
      });
    }

    const questions =
      getQuestions().filter(
        question =>
          String(question.examId) ===
            String(exam.id) &&
          String(question.schoolId) ===
            String(req.user.schoolId)
      );

    const answers =
      req.body.answers || {};

    let score = 0;
    let totalMarks = 0;

    for (const question of questions) {
      const points =
        Number(question.points || 1);

      totalMarks += points;

      const submitted =
        answers[question.id];

      if (
        submitted !== undefined &&
        Number(submitted) ===
          Number(question.answer)
      ) {
        score += points;
      }
    }

    const percentage =
      totalMarks > 0
        ? Math.round(
            (score / totalMarks) * 100
          )
        : 0;

    const results = getResults();

    const result = {
      id: createId("result"),
      schoolId: req.user.schoolId,
      examId: exam.id,
      studentId: req.user.id,
      score,
      totalMarks,
      percentage,
      answers,
      submittedAt: now()
    };

    results.push(result);
    saveResults(results);

    res.json({
      ok: true,
      message: "Exam submitted successfully",
      result
    });
  }
);

// ============================================================
// RESULTS
// ============================================================

app.get(
  "/api/results",
  ...requireRole(
    "school_admin",
    "teacher",
    "student"
  ),
  (req, res) => {
    let results =
      getResults().filter(
        result =>
          String(result.schoolId) ===
          String(req.user.schoolId)
      );

    if (req.user.role === "student") {
      results = results.filter(
        result =>
          String(result.studentId) ===
          String(req.user.id)
      );
    }

    res.json({
      ok: true,
      results
    });
  }
);

// ============================================================
// ANNOUNCEMENTS
// ============================================================

app.get(
  "/api/announcements",
  ...requireRole(
    "school_admin",
    "teacher",
    "student"
  ),
  (req, res) => {
    const announcements =
      getAnnouncements().filter(
        announcement =>
          String(announcement.schoolId) ===
          String(req.user.schoolId)
      );

    res.json({
      ok: true,
      announcements
    });
  }
);

app.post(
  "/api/announcements",
  ...requireRole("school_admin", "teacher"),
  (req, res) => {
    const {
      title,
      message
    } = req.body;

    if (!title || !message) {
      return res.status(400).json({
        ok: false,
        error: "Title and message are required"
      });
    }

    const announcements =
      getAnnouncements();

    const announcement = {
      id: createId("announcement"),
      schoolId: req.user.schoolId,
      title: clean(title),
      message: clean(message),
      createdBy: req.user.id,
      createdAt: now(),
      updatedAt: now()
    };

    announcements.push(announcement);
    saveAnnouncements(announcements);

    res.status(201).json({
      ok: true,
      announcement
    });
  }
);

// ============================================================
// SCHOOL ADMIN SUMMARY
// ============================================================

app.get(
  "/api/admin/summary",
  ...requireRole("school_admin"),
  (req, res) => {
    const schoolId = req.user.schoolId;

    const users = getUsers().filter(
      user =>
        String(user.schoolId) ===
        String(schoolId)
    );

    const students = users.filter(
      user => user.role === "student"
    );

    const teachers = users.filter(
      user => user.role === "teacher"
    );

    const subjects =
      getSubjects().filter(
        subject =>
          String(subject.schoolId) ===
          String(schoolId)
      );

    const exams =
      getExams().filter(
        exam =>
          String(exam.schoolId) ===
          String(schoolId)
      );

    const results =
      getResults().filter(
        result =>
          String(result.schoolId) ===
          String(schoolId)
      );

    res.json({
      ok: true,
      summary: {
        students: students.length,
        teachers: teachers.length,
        subjects: subjects.length,
        exams: exams.length,
        results: results.length
      }
    });
  }
);

// ============================================================
// TEACHER SUMMARY
// ============================================================

app.get(
  "/api/teacher/summary",
  ...requireRole("teacher"),
  (req, res) => {
    const schoolId = req.user.schoolId;

    const subjects =
      getSubjects().filter(
        subject =>
          String(subject.schoolId) ===
          String(schoolId)
      );

    const exams =
      getExams().filter(
        exam =>
          String(exam.schoolId) ===
          String(schoolId)
      );

    const students =
      getUsers().filter(
        user =>
          String(user.schoolId) ===
            String(schoolId) &&
          user.role === "student"
      );

    res.json({
      ok: true,
      summary: {
        subjects: subjects.length,
        exams: exams.length,
        students: students.length
      }
    });
  }
);

// ============================================================
// STUDENT SUMMARY
// ============================================================

app.get(
  "/api/student/summary",
  ...requireRole("student"),
  (req, res) => {
    const schoolId = req.user.schoolId;

    const exams =
      getExams().filter(
        exam =>
          String(exam.schoolId) ===
          String(schoolId)
      );

    const results =
      getResults().filter(
        result =>
          String(result.studentId) ===
          String(req.user.id)
      );

    const announcements =
      getAnnouncements().filter(
        announcement =>
          String(announcement.schoolId) ===
          String(schoolId)
      );

    res.json({
      ok: true,
      summary: {
        exams: exams.length,
        completedExams: results.length,
        announcements: announcements.length
      }
    });
  }
);

// ============================================================
// SUPERADMIN - SCHOOLS
// ============================================================

app.get(
  "/api/admin/schools",
  ...requireRole("superadmin"),
  (req, res) => {
    const schools = getSchools();

    const users = getUsers();

    const enriched = schools.map(
      school => ({
        ...school,
        userCount: users.filter(
          user =>
            String(user.schoolId) ===
            String(school.id)
        ).length,
        studentCount: users.filter(
          user =>
            String(user.schoolId) ===
              String(school.id) &&
            user.role === "student"
        ).length,
        teacherCount: users.filter(
          user =>
            String(user.schoolId) ===
              String(school.id) &&
            user.role === "teacher"
        ).length
      })
    );

    res.json({
      ok: true,
      schools: enriched
    });
  }
);

// ============================================================
// SUPERADMIN - CREATE SCHOOL
// ============================================================

app.post(
  "/api/admin/schools",
  ...requireRole("superadmin"),
  async (req, res) => {
    try {
      const {
        name,
        motto,
        adminName,
        adminUsername,
        adminEmail,
        adminPassword
      } = req.body;

      if (
        !name ||
        !adminName ||
        !adminUsername ||
        !adminEmail ||
        !adminPassword
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "School and administrator details are required"
        });
      }

      const schools = getSchools();
      const users = getUsers();

      const normalizedEmail =
        normalizeEmail(adminEmail);

      const normalizedUsername =
        normalizeUsername(adminUsername);

      if (
        users.some(
          user =>
            normalizeEmail(user.email) ===
            normalizedEmail
        )
      ) {
        return res.status(409).json({
          ok: false,
          error: "Admin email already exists"
        });
      }

      if (
        users.some(
          user =>
            normalizeUsername(user.username) ===
            normalizedUsername
        )
      ) {
        return res.status(409).json({
          ok: false,
          error: "Admin username already exists"
        });
      }

      const school = {
        id: createId("school"),
        name: clean(name),
        motto: clean(motto),
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
        await bcrypt.hash(
          String(adminPassword),
          12
        );

      const admin = {
        id: createId("user"),
        fullName: clean(adminName),
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

      users.push(admin);
      saveUsers(users);

      res.status(201).json({
        ok: true,
        message: "School created successfully",
        school,
        admin: safeUser(admin)
      });
    } catch (error) {
      console.error(
        "SUPERADMIN CREATE SCHOOL ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error: "Unable to create school"
      });
    }
  }
);

// ============================================================
// SUPERADMIN - UPDATE SCHOOL
// ============================================================

app.put(
  "/api/admin/schools/:id",
  ...requireRole("superadmin"),
  (req, res) => {
    const schools = getSchools();

    const index = schools.findIndex(
      school =>
        String(school.id) ===
        String(req.params.id)
    );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error: "School not found"
      });
    }

    const school = schools[index];

    if (req.body.name !== undefined) {
      school.name = clean(req.body.name);
    }

    if (req.body.motto !== undefined) {
      school.motto = clean(req.body.motto);
    }

    if (req.body.logo !== undefined) {
      school.logo = clean(req.body.logo);
    }

    if (req.body.primaryColor !== undefined) {
      school.primaryColor =
        clean(req.body.primaryColor);
    }

    if (req.body.secondaryColor !== undefined) {
      school.secondaryColor =
        clean(req.body.secondaryColor);
    }

    if (req.body.theme !== undefined) {
      school.theme =
        clean(req.body.theme);
    }

    if (req.body.active !== undefined) {
      school.active =
        Boolean(req.body.active);
    }

    school.updatedAt = now();

    schools[index] = school;
    saveSchools(schools);

    res.json({
      ok: true,
      message: "School updated",
      school
    });
  }
);

// ============================================================
// SUPERADMIN - ALL USERS
// ============================================================

app.get(
  "/api/admin/users",
  ...requireRole("superadmin"),
  (req, res) => {
    const users = getUsers();
    const schools = getSchools();

    const result = users.map(
      user => ({
        ...safeUser(user),
        schoolName:
          schools.find(
            school =>
              String(school.id) ===
              String(user.schoolId)
          )?.name || null
      })
    );

    res.json({
      ok: true,
      users: result
    });
  }
);

// ============================================================
// SUPERADMIN SUMMARY
// ============================================================

app.get(
  "/api/admin/super-summary",
  ...requireRole("superadmin"),
  (req, res) => {
    const users = getUsers();
    const schools = getSchools();

    res.json({
      ok: true,
      summary: {
        schools: schools.length,
        activeSchools:
          schools.filter(
            school => school.active !== false
          ).length,
        users: users.length,
        admins:
          users.filter(
            user =>
              user.role === "school_admin"
          ).length,
        teachers:
          users.filter(
            user =>
              user.role === "teacher"
          ).length,
        students:
          users.filter(
            user =>
              user.role === "student"
          ).length
      }
    });
  }
);

// ============================================================
// SUPERADMIN SETTINGS
// ============================================================

app.put(
  "/api/admin/settings",
  ...requireRole("superadmin"),
  (req, res) => {
    const settings = getSettings();

    const allowed = [
      "platformName",
      "platformDescription",
      "defaultTheme",
      "maintenanceMode",
      "primaryColor",
      "secondaryColor"
    ];

    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        settings[key] = req.body[key];
      }
    }

    saveSettings(settings);

    res.json({
      ok: true,
      message: "Platform settings updated",
      settings
    });
  }
);

// ============================================================
// ENSURE SUPERADMIN
// ============================================================

async function ensureSuperadmin() {
  const email = normalizeEmail(
    process.env.SUPERADMIN_EMAIL
  );

  const username = normalizeUsername(
    process.env.SUPERADMIN_USERNAME ||
      "superadmin"
  );

  const password =
    process.env.SUPERADMIN_PASSWORD;

  const fullName =
    process.env.SUPERADMIN_NAME ||
    "SchoolHub Super Admin";

  if (!email || !password) {
    console.log(
      "SUPERADMIN: Environment credentials not configured."
    );

    return;
  }

  const users = getUsers();

  let user =
    users.find(
      item =>
        normalizeEmail(item.email) ===
        email
    ) ||
    users.find(
      item =>
        normalizeUsername(item.username) ===
        username
    );

  if (user) {
    user.role = "superadmin";
    user.schoolId = null;
    user.active = true;
    user.updatedAt = now();

    saveUsers(users);

    console.log(
      `SUPERADMIN: ${user.email} is configured as superadmin.`
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

  users.push(user);
  saveUsers(users);

  console.log(
    `SUPERADMIN: Created ${email}`
  );
}

// ============================================================
// DASHBOARD REDIRECT
// ============================================================

app.get("/dashboard", (req, res) => {
  if (
    req.isAuthenticated &&
    req.isAuthenticated() &&
    req.user
  ) {
    return res.redirect(
      roleRedirect(req.user)
    );
  }

  res.redirect("/login.html");
});

// ============================================================
// STATIC FRONTEND
// ============================================================

app.use(
  express.static(PUBLIC_DIR, {
    index: "index.html"
  })
);

// ============================================================
// PROTECTED DASHBOARD FALLBACK
// ============================================================

app.get(
  "/superadmin.html",
  (req, res, next) => {
    if (
      !req.isAuthenticated ||
      !req.isAuthenticated() ||
      !req.user
    ) {
      return res.redirect("/login.html");
    }

    if (req.user.role !== "superadmin") {
      return res.redirect(
        roleRedirect(req.user)
      );
    }

    next();
  },
  express.static(
    path.join(PUBLIC_DIR, "superadmin.html")
  )
);

app.get(
  "/admin.html",
  (req, res, next) => {
    if (
      !req.isAuthenticated ||
      !req.isAuthenticated() ||
      !req.user
    ) {
      return res.redirect("/login.html");
    }

    if (req.user.role !== "school_admin") {
      return res.redirect(
        roleRedirect(req.user)
      );
    }

    next();
  },
  express.static(
    path.join(PUBLIC_DIR, "admin.html")
  )
);

app.get(
  "/teacher.html",
  (req, res, next) => {
    if (
      !req.isAuthenticated ||
      !req.isAuthenticated() ||
      !req.user
    ) {
      return res.redirect("/login.html");
    }

    if (req.user.role !== "teacher") {
      return res.redirect(
        roleRedirect(req.user)
      );
    }

    next();
  },
  express.static(
    path.join(PUBLIC_DIR, "teacher.html")
  )
);

app.get(
  "/student.html",
  (req, res, next) => {
    if (
      !req.isAuthenticated ||
      !req.isAuthenticated() ||
      !req.user
    ) {
      return res.redirect("/login.html");
    }

    if (req.user.role !== "student") {
      return res.redirect(
        roleRedirect(req.user)
      );
    }

    next();
  },
  express.static(
    path.join(PUBLIC_DIR, "student.html")
  )
);

// ============================================================
// 404
// ============================================================

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({
      ok: false,
      error: "API route not found"
    });
  }

  res.status(404).send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>404 - SchoolHub Pro</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
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
            border-radius: 18px;
            text-align: center;
            box-shadow: 0 15px 50px rgba(0,0,0,.08);
          }
          a {
            color: #2563eb;
            text-decoration: none;
          }
        </style>
      </head>
      <body>
        <div class="box">
          <h1>404</h1>
          <p>Page not found.</p>
          <a href="/login.html">Back to login</a>
        </div>
      </body>
    </html>
  `);
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
    error: "Internal server error"
  });
});

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

let server;

async function shutdown(signal) {
  console.log(`${signal} received. Shutting down...`);

  if (!server) {
    process.exit(0);
  }

  server.close(() => {
    console.log("HTTP server closed.");
    process.exit(0);
  });

  setTimeout(() => {
    console.log(
      "Forced shutdown after timeout."
    );

    process.exit(0);
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

// ============================================================
// START SERVER
// ============================================================

async function startServer() {
  try {
    await ensureSuperadmin();

    server = app.listen(
      PORT,
      HOST,
      () => {
        console.log("");
        console.log(
          "============================================"
        );
        console.log(
          "        SCHOOLHUB PRO SERVER"
        );
        console.log(
          "============================================"
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
          `URL: ${
            IS_PRODUCTION
              ? "Railway deployment"
              : `http://localhost:${PORT}`
          }`
        );
        console.log(
          "============================================"
        );
        console.log("");
      }
    );
  } catch (error) {
    console.error(
      "SERVER START ERROR:",
      error
    );

    process.exit(1);
  }
}

startServer();
