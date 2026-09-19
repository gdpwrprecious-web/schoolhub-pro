// ============================================================
// SCHOOLHUB PRO
// COMPLETE MAIN SERVER
// Multi-School School Management + CBT Platform
// ============================================================

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
// CONFIG
// ============================================================

const app = express();

const PORT = Number(process.env.PORT || 3000);
const HOST = "0.0.0.0";

const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PRODUCTION = NODE_ENV === "production";

const STORAGE_ROOT =
  process.env.STORAGE_ROOT ||
  path.join(__dirname, "storage");

const DATA_DIR = path.join(STORAGE_ROOT, "data");
const UPLOADS_DIR = path.join(STORAGE_ROOT, "uploads");
const PROFILE_DIR = path.join(UPLOADS_DIR, "profiles");
const SCHOOL_DIR = path.join(UPLOADS_DIR, "schools");

const PUBLIC_DIR = path.join(__dirname, "public");

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "CHANGE_THIS_SESSION_SECRET";

const GOOGLE_CLIENT_ID =
  process.env.GOOGLE_CLIENT_ID || "";

const GOOGLE_CLIENT_SECRET =
  process.env.GOOGLE_CLIENT_SECRET || "";

const GOOGLE_CALLBACK_URL =
  process.env.GOOGLE_CALLBACK_URL ||
  `http://localhost:${PORT}/auth/google/callback`;

const GOOGLE_CONFIGURED =
  Boolean(GOOGLE_CLIENT_ID) &&
  Boolean(GOOGLE_CLIENT_SECRET) &&
  Boolean(GOOGLE_CALLBACK_URL);

// ============================================================
// DIRECTORIES
// ============================================================

[
  STORAGE_ROOT,
  DATA_DIR,
  UPLOADS_DIR,
  PROFILE_DIR,
  SCHOOL_DIR,
  PUBLIC_DIR
].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// ============================================================
// JSON DATABASE FILES
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
    "Smart school management and CBT platform.",
  defaultTheme: "light",
  maintenanceMode: false,
  primaryColor: "#2563eb",
  secondaryColor: "#16a34a"
};

// ============================================================
// DATABASE HELPERS
// ============================================================

function ensureFile(file, defaultValue) {
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
    ensureFile(file, fallback);

    const text = fs.readFileSync(file, "utf8").trim();

    if (!text) {
      return fallback;
    }

    return JSON.parse(text);
  } catch (error) {
    console.error(
      "READ JSON ERROR:",
      file,
      error.message
    );

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

Object.entries(FILES).forEach(([key, file]) => {
  if (key === "settings") {
    ensureFile(file, DEFAULT_SETTINGS);
  } else {
    ensureFile(file, []);
  }
});

// ============================================================
// HELPERS
// ============================================================

function id(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function now() {
  return new Date().toISOString();
}

function clean(value) {
  return String(value ?? "").trim();
}

function email(value) {
  return clean(value).toLowerCase();
}

function username(value) {
  return clean(value).toLowerCase();
}

function users() {
  return readJson(FILES.users, []);
}

function schools() {
  return readJson(FILES.schools, []);
}

function settings() {
  return {
    ...DEFAULT_SETTINGS,
    ...readJson(FILES.settings, DEFAULT_SETTINGS)
  };
}

function subjects() {
  return readJson(FILES.subjects, []);
}

function exams() {
  return readJson(FILES.exams, []);
}

function questions() {
  return readJson(FILES.questions, []);
}

function results() {
  return readJson(FILES.results, []);
}

function announcements() {
  return readJson(FILES.announcements, []);
}

function saveUsers(value) {
  writeJson(FILES.users, value);
}

function saveSchools(value) {
  writeJson(FILES.schools, value);
}

function saveSettings(value) {
  writeJson(FILES.settings, value);
}

function saveSubjects(value) {
  writeJson(FILES.subjects, value);
}

function saveExams(value) {
  writeJson(FILES.exams, value);
}

function saveQuestions(value) {
  writeJson(FILES.questions, value);
}

function saveResults(value) {
  writeJson(FILES.results, value);
}

function saveAnnouncements(value) {
  writeJson(FILES.announcements, value);
}

function getUser(userId) {
  return users().find(
    user =>
      String(user.id) === String(userId)
  );
}

function getSchool(schoolId) {
  return schools().find(
    school =>
      String(school.id) === String(schoolId)
  );
}

function schoolForUser(user) {
  if (!user || !user.schoolId) {
    return null;
  }

  return getSchool(user.schoolId);
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
    createdAt: user.createdAt || null,
    updatedAt: user.updatedAt || null
  };
}

// ============================================================
// ROLE REDIRECT
// ============================================================

function dashboardFor(user) {
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
// RAILWAY PROXY
// ============================================================

if (IS_PRODUCTION) {
  app.set("trust proxy", 1);
}

// ============================================================
// EXPRESS
// ============================================================

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

// ============================================================
// SESSION
// ============================================================

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

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((userId, done) => {
  const user = getUser(userId);

  if (!user) {
    return done(null, false);
  }

  if (user.active === false) {
    return done(null, false);
  }

  done(null, user);
});

// ============================================================
// GOOGLE AUTH
// ============================================================

if (GOOGLE_CONFIGURED) {
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

          const googleEmail =
            profile.emails &&
            profile.emails[0]
              ? email(profile.emails[0].value)
              : "";

          let user =
            allUsers.find(
              item =>
                item.googleId === googleId
            ) ||
            allUsers.find(
              item =>
                googleEmail &&
                email(item.email) ===
                  googleEmail
            );

          if (!user) {
            return done(null, false, {
              message:
                "google_account_not_registered"
            });
          }

          if (user.active === false) {
            return done(null, false, {
              message: "account_disabled"
            });
          }

          let changed = false;

          if (!user.googleId) {
            user.googleId = googleId;
            changed = true;
          }

          user.provider = "google";
          user.updatedAt = now();

          if (
            !user.profilePicture &&
            profile.photos &&
            profile.photos[0]
          ) {
            user.profilePicture =
              profile.photos[0].value;

            changed = true;
          }

          if (changed) {
            saveUsers(allUsers);
          }

          done(null, user);
        } catch (error) {
          console.error(
            "GOOGLE STRATEGY ERROR:",
            error
          );

          done(error);
        }
      }
    )
  );
}

// ============================================================
// FILE UPLOAD
// ============================================================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === "profilePicture") {
      cb(null, PROFILE_DIR);
      return;
    }

    if (
      file.fieldname === "logo" ||
      file.fieldname === "schoolLogo"
    ) {
      cb(null, SCHOOL_DIR);
      return;
    }

    cb(null, UPLOADS_DIR);
  },

  filename: (req, file, cb) => {
    const extension =
      path.extname(file.originalname) ||
      ".bin";

    cb(
      null,
      `${Date.now()}-${crypto
        .randomBytes(8)
        .toString("hex")}${extension}`
    );
  }
});

const upload = multer({
  storage,

  limits: {
    fileSize: 5 * 1024 * 1024
  },

  fileFilter: (req, file, cb) => {
    const allowed = [
      "image/jpeg",
      "image/png",
      "image/webp",
      "image/gif"
    ];

    if (allowed.includes(file.mimetype)) {
      return cb(null, true);
    }

    cb(
      new Error(
        "Only JPG, PNG, WEBP and GIF images are allowed."
      )
    );
  }
});

// ============================================================
// SERVE UPLOADS
// ============================================================

app.use(
  "/uploads",
  express.static(UPLOADS_DIR)
);

// ============================================================
// AUTH MIDDLEWARE
// ============================================================

function requireAuth(req, res, next) {
  if (
    req.isAuthenticated &&
    req.isAuthenticated() &&
    req.user &&
    req.user.active !== false
  ) {
    return next();
  }

  if (req.path.startsWith("/api/")) {
    return res.status(401).json({
      ok: false,
      authenticated: false,
      error: "Authentication required"
    });
  }

  res.redirect("/login.html");
}

function requireRole(...allowedRoles) {
  return [
    requireAuth,

    (req, res, next) => {
      if (
        !req.user ||
        !allowedRoles.includes(req.user.role)
      ) {
        return res.status(403).json({
          ok: false,
          error: "Access denied"
        });
      }

      next();
    }
  ];
}

function requireSchoolAccess(
  req,
  res,
  next
) {
  if (req.user.role === "superadmin") {
    return next();
  }

  if (!req.user.schoolId) {
    return res.status(403).json({
      ok: false,
      error: "No school assigned"
    });
  }

  next();
}

// ============================================================
// HEALTH
// ============================================================

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    status: "online",
    service: "SchoolHub Pro",
    version: "7.0.0",
    environment: NODE_ENV,
    port: PORT,
    storage: STORAGE_ROOT,
    googleAuth:
      GOOGLE_CONFIGURED
        ? "CONFIGURED"
        : "NOT CONFIGURED",
    uploads: "/uploads",
    time: now()
  });
});

// ============================================================
// PLATFORM
// ============================================================

app.get("/api/platform", (req, res) => {
  res.json({
    ok: true,
    platform: settings()
  });
});

app.get("/api/platform-config", (req, res) => {
  const config = settings();

  res.json({
    ok: true,
    platformName: config.platformName,
    platformDescription:
      config.platformDescription,
    defaultTheme: config.defaultTheme,
    primaryColor: config.primaryColor,
    secondaryColor:
      config.secondaryColor
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

  const user = getUser(req.user.id);

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
    school: schoolForUser(user)
  });
});

// ============================================================
// REGISTER SCHOOL
// ============================================================

async function registerSchool(req, res) {
  try {
    const {
      schoolName,
      motto,
      fullName,
      username: rawUsername,
      email: rawEmail,
      password
    } = req.body;

    const normalizedEmail =
      email(rawEmail);

    const normalizedUsername =
      username(rawUsername);

    if (
      !schoolName ||
      !fullName ||
      !normalizedUsername ||
      !normalizedEmail ||
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
        error:
          "Password must be at least 6 characters"
      });
    }

    const allUsers = users();

    if (
      allUsers.some(
        user =>
          email(user.email) ===
          normalizedEmail
      )
    ) {
      return res.status(409).json({
        ok: false,
        error: "Email already exists"
      });
    }

    if (
      allUsers.some(
        user =>
          username(user.username) ===
          normalizedUsername
      )
    ) {
      return res.status(409).json({
        ok: false,
        error: "Username already exists"
      });
    }

    const school = {
      id: id("school"),
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

    const allSchools = schools();

    allSchools.push(school);

    saveSchools(allSchools);

    const passwordHash =
      await bcrypt.hash(
        String(password),
        12
      );

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

    allUsers.push(user);

    saveUsers(allUsers);

    req.login(user, error => {
      if (error) {
        console.error(
          "REGISTER LOGIN ERROR:",
          error
        );

        return res.status(500).json({
          ok: false,
          error:
            "Account created but automatic login failed"
        });
      }

      req.session.save(saveError => {
        if (saveError) {
          console.error(
            "REGISTER SESSION ERROR:",
            saveError
          );

          return res.status(500).json({
            ok: false,
            error:
              "Account created but session could not be saved"
          });
        }

        res.json({
          ok: true,
          message:
            "School account created successfully",
          user: safeUser(user),
          school,
          redirect: "/admin.html"
        });
      });
    });
  } catch (error) {
    console.error(
      "REGISTER ERROR:",
      error
    );

    res.status(500).json({
      ok: false,
      error: "Registration failed"
    });
  }
}

app.post(
  "/api/register",
  registerSchool
);

app.post(
  "/api/signup",
  registerSchool
);

// ============================================================
// LOGIN
// ============================================================

app.post(
  "/api/login",
  async (req, res) => {
    try {
      const identifier =
        clean(req.body.identifier) ||
        clean(req.body.email) ||
        clean(req.body.username);

      const password =
        String(req.body.password || "");

      if (!identifier || !password) {
        return res.status(400).json({
          ok: false,
          error:
            "Username/email and password are required"
        });
      }

      const normalized =
        identifier.toLowerCase();

      const allUsers = users();

      const user = allUsers.find(
        item =>
          email(item.email) ===
            normalized ||
          username(item.username) ===
            normalized
      );

      if (!user) {
        return res.status(401).json({
          ok: false,
          error:
            "Invalid username/email or password"
        });
      }

      if (user.active === false) {
        return res.status(403).json({
          ok: false,
          error:
            "This account has been disabled"
        });
      }

      if (!user.passwordHash) {
        return res.status(401).json({
          ok: false,
          error:
            "This account uses Google Sign-In"
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
          error:
            "Invalid username/email or password"
        });
      }

      // Remove old session.
      req.session.regenerate(
        regenerateError => {
          if (regenerateError) {
            console.error(
              "SESSION REGENERATE ERROR:",
              regenerateError
            );

            return res.status(500).json({
              ok: false,
              error:
                "Could not create login session"
            });
          }

          req.login(
            user,
            loginError => {
              if (loginError) {
                console.error(
                  "LOGIN SESSION ERROR:",
                  loginError
                );

                return res.status(500).json({
                  ok: false,
                  error:
                    "Could not create login session"
                });
              }

              req.session.save(
                saveError => {
                  if (saveError) {
                    console.error(
                      "SESSION SAVE ERROR:",
                      saveError
                    );

                    return res.status(500).json({
                      ok: false,
                      error:
                        "Login session could not be saved"
                    });
                  }

                  res.json({
                    ok: true,
                    message:
                      "Login successful",
                    user: safeUser(user),
                    school:
                      schoolForUser(user),
                    redirect:
                      dashboardFor(user)
                  });
                }
              );
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
          "An internal error occurred during login"
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
    req.logout(logoutError => {
      if (logoutError) {
        console.error(
          "LOGOUT ERROR:",
          logoutError
        );

        return res.status(500).json({
          ok: false,
          error: "Logout failed"
        });
      }

      req.session.destroy(
        sessionError => {
          if (sessionError) {
            console.error(
              "SESSION DESTROY ERROR:",
              sessionError
            );
          }

          res.clearCookie(
            "schoolhub.sid",
            {
              httpOnly: true,
              secure: IS_PRODUCTION,
              sameSite: "lax",
              path: "/"
            }
          );

          res.json({
            ok: true,
            redirect: "/login.html"
          });
        }
      );
    });
  }
);

app.get(
  "/logout",
  (req, res) => {
    req.logout(() => {
      req.session.destroy(() => {
        res.clearCookie(
          "schoolhub.sid",
          {
            httpOnly: true,
            secure: IS_PRODUCTION,
            sameSite: "lax",
            path: "/"
          }
        );

        res.redirect(
          "/login.html"
        );
      });
    });
  }
);

// ============================================================
// GOOGLE LOGIN
// ============================================================

app.get(
  "/auth/google",
  (req, res, next) => {
    if (!GOOGLE_CONFIGURED) {
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
        session: true
      }
    )(req, res, next);
  }
);

app.get(
  "/auth/google/callback",
  (req, res, next) => {
    if (!GOOGLE_CONFIGURED) {
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
            info?.message ||
            "google_login_failed";

          return res.redirect(
            `/login.html?error=${encodeURIComponent(
              message
            )}`
          );
        }

        req.login(
          user,
          loginError => {
            if (loginError) {
              console.error(
                "GOOGLE LOGIN ERROR:",
                loginError
              );

              return res.redirect(
                "/login.html?error=google_session_failed"
              );
            }

            req.session.save(
              saveError => {
                if (saveError) {
                  console.error(
                    "GOOGLE SESSION SAVE ERROR:",
                    saveError
                  );

                  return res.redirect(
                    "/login.html?error=google_session_failed"
                  );
                }

                res.redirect(
                  dashboardFor(user)
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
// SCHOOL INFORMATION
// ============================================================

app.get(
  "/api/school",
  ...requireRole(
    "school_admin",
    "teacher",
    "student",
    "superadmin"
  ),
  (req, res) => {
    if (
      req.user.role ===
      "superadmin"
    ) {
      return res.json({
        ok: true,
        school: null
      });
    }

    const school =
      schoolForUser(req.user);

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
  upload.single("logo"),
  (req, res) => {
    try {
      const allSchools =
        schools();

      const index =
        allSchools.findIndex(
          school =>
            String(school.id) ===
            String(
              req.user.schoolId
            )
        );

      if (index === -1) {
        return res.status(404).json({
          ok: false,
          error: "School not found"
        });
      }

      const school =
        allSchools[index];

      if (req.body.name !== undefined) {
        school.name =
          clean(req.body.name);
      }

      if (req.body.motto !== undefined) {
        school.motto =
          clean(req.body.motto);
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

      if (req.file) {
        school.logo =
          `/uploads/schools/${req.file.filename}`;
      }

      school.updatedAt = now();

      allSchools[index] = school;

      saveSchools(allSchools);

      res.json({
        ok: true,
        message:
          "School branding updated",
        school
      });
    } catch (error) {
      console.error(
        "BRANDING ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Could not update branding"
      });
    }
  }
);

// ============================================================
// PROFILE PICTURE UPLOAD
// ============================================================

app.post(
  "/api/profile/picture",
  ...requireRole(
    "superadmin",
    "school_admin",
    "teacher",
    "student"
  ),
  upload.single("profilePicture"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        ok: false,
        error:
          "Please select a profile picture"
      });
    }

    const allUsers =
      users();

    const index =
      allUsers.findIndex(
        user =>
          String(user.id) ===
          String(req.user.id)
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error: "User not found"
      });
    }

    const user =
      allUsers[index];

    user.profilePicture =
      `/uploads/profiles/${req.file.filename}`;

    user.updatedAt = now();

    allUsers[index] = user;

    saveUsers(allUsers);

    res.json({
      ok: true,
      message:
        "Profile picture updated",
      user: safeUser(user)
    });
  }
);

// ============================================================
// PROFILE UPDATE
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
      const allUsers =
        users();

      const index =
        allUsers.findIndex(
          user =>
            String(user.id) ===
            String(req.user.id)
        );

      if (index === -1) {
        return res.status(404).json({
          ok: false,
          error: "User not found"
        });
      }

      const user =
        allUsers[index];

      if (
        req.body.fullName !==
        undefined
      ) {
        user.fullName =
          clean(req.body.fullName);
      }

      if (
        req.body.username !==
        undefined
      ) {
        const newUsername =
          username(
            req.body.username
          );

        const duplicate =
          allUsers.some(
            item =>
              item.id !== user.id &&
              username(
                item.username
              ) === newUsername
          );

        if (duplicate) {
          return res.status(409).json({
            ok: false,
            error:
              "Username already exists"
          });
        }

        user.username =
          newUsername;
      }

      if (
        req.body.email !==
        undefined
      ) {
        const newEmail =
          email(req.body.email);

        const duplicate =
          allUsers.some(
            item =>
              item.id !== user.id &&
              email(item.email) ===
                newEmail
          );

        if (duplicate) {
          return res.status(409).json({
            ok: false,
            error:
              "Email already exists"
          });
        }

        user.email =
          newEmail;
      }

      if (req.body.password) {
        user.passwordHash =
          await bcrypt.hash(
            String(req.body.password),
            12
          );
      }

      user.updatedAt = now();

      allUsers[index] = user;

      saveUsers(allUsers);

      res.json({
        ok: true,
        message:
          "Profile updated",
        user: safeUser(user)
      });
    } catch (error) {
      console.error(
        "PROFILE UPDATE ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Could not update profile"
      });
    }
  }
);

// ============================================================
// USER MANAGEMENT
// ============================================================

app.get(
  "/api/users",
  ...requireRole(
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    let allUsers =
      users();

    if (
      req.user.role !==
      "superadmin"
    ) {
      allUsers =
        allUsers.filter(
          user =>
            String(user.schoolId) ===
            String(
              req.user.schoolId
            )
        );
    }

    res.json({
      ok: true,
      users:
        allUsers.map(safeUser)
    });
  }
);

app.post(
  "/api/users",
  ...requireRole(
    "school_admin",
    "superadmin"
  ),
  async (req, res) => {
    try {
      const {
        fullName,
        username: rawUsername,
        email: rawEmail,
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
        !rawUsername ||
        !rawEmail ||
        !password ||
        !role
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "All required fields are required"
        });
      }

      if (
        !allowedRoles.includes(role)
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Only teacher and student accounts can be created here"
        });
      }

      const targetSchoolId =
        req.user.role ===
        "superadmin"
          ? schoolId
          : req.user.schoolId;

      if (!targetSchoolId) {
        return res.status(400).json({
          ok: false,
          error:
            "School is required"
        });
      }

      if (
        !getSchool(
          targetSchoolId
        )
      ) {
        return res.status(404).json({
          ok: false,
          error:
            "School not found"
        });
      }

      const normalizedEmail =
        email(rawEmail);

      const normalizedUsername =
        username(rawUsername);

      const allUsers =
        users();

      if (
        allUsers.some(
          user =>
            email(user.email) ===
            normalizedEmail
        )
      ) {
        return res.status(409).json({
          ok: false,
          error:
            "Email already exists"
        });
      }

      if (
        allUsers.some(
          user =>
            username(
              user.username
            ) ===
            normalizedUsername
        )
      ) {
        return res.status(409).json({
          ok: false,
          error:
            "Username already exists"
        });
      }

      const passwordHash =
        await bcrypt.hash(
          String(password),
          12
        );

      const user = {
        id: id("user"),
        fullName:
          clean(fullName),
        username:
          normalizedUsername,
        email:
          normalizedEmail,
        passwordHash,
        role,
        schoolId:
          targetSchoolId,
        profilePicture: "",
        provider: "local",
        active: true,
        createdAt: now(),
        updatedAt: now()
      };

      allUsers.push(user);

      saveUsers(allUsers);

      res.status(201).json({
        ok: true,
        message:
          "User created successfully",
        user: safeUser(user)
      });
    } catch (error) {
      console.error(
        "CREATE USER ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Could not create user"
      });
    }
  }
);

// ============================================================
// UPDATE USER
// ============================================================

app.put(
  "/api/users/:id",
  ...requireRole(
    "school_admin",
    "superadmin"
  ),
  async (req, res) => {
    try {
      const allUsers =
        users();

      const index =
        allUsers.findIndex(
          user =>
            String(user.id) ===
            String(req.params.id)
        );

      if (index === -1) {
        return res.status(404).json({
          ok: false,
          error:
            "User not found"
        });
      }

      const user =
        allUsers[index];

      if (
        req.user.role !==
          "superadmin" &&
        String(
          user.schoolId
        ) !==
          String(
            req.user.schoolId
          )
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "Access denied"
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
          username(
            req.body.username
          );
      }

      if (
        req.body.email !==
        undefined
      ) {
        user.email =
          email(req.body.email);
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
        req.user.role ===
          "superadmin" &&
        req.body.role &&
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

        if (
          user.role ===
          "superadmin"
        ) {
          user.schoolId = null;
        }
      }

      user.updatedAt = now();

      allUsers[index] = user;

      saveUsers(allUsers);

      res.json({
        ok: true,
        message:
          "User updated",
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
          "Could not update user"
      });
    }
  }
);

// ============================================================
// DELETE USER
// ============================================================

app.delete(
  "/api/users/:id",
  ...requireRole(
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    const allUsers =
      users();

    const index =
      allUsers.findIndex(
        user =>
          String(user.id) ===
          String(req.params.id)
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error:
          "User not found"
      });
    }

    const user =
      allUsers[index];

    if (
      req.user.role !==
        "superadmin" &&
      String(
        user.schoolId
      ) !==
        String(
          req.user.schoolId
        )
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Access denied"
      });
    }

    if (
      String(user.id) ===
      String(req.user.id)
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "You cannot delete yourself"
      });
    }

    allUsers.splice(
      index,
      1
    );

    saveUsers(allUsers);

    res.json({
      ok: true,
      message:
        "User deleted"
    });
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
    const list =
      subjects().filter(
        subject =>
          String(
            subject.schoolId
          ) ===
          String(
            req.user.schoolId
          )
      );

    res.json({
      ok: true,
      subjects: list
    });
  }
);

app.post(
  "/api/subjects",
  ...requireRole(
    "school_admin",
    "teacher"
  ),
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
          "Subject name is required"
      });
    }

    const list =
      subjects();

    const subject = {
      id: id("subject"),
      schoolId:
        req.user.schoolId,
      name:
        clean(name),
      code:
        clean(code),
      description:
        clean(description),
      createdBy:
        req.user.id,
      createdAt: now(),
      updatedAt: now()
    };

    list.push(subject);

    saveSubjects(list);

    res.status(201).json({
      ok: true,
      subject
    });
  }
);

app.put(
  "/api/subjects/:id",
  ...requireRole(
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    const list =
      subjects();

    const index =
      list.findIndex(
        item =>
          String(item.id) ===
            String(
              req.params.id
            ) &&
          String(
            item.schoolId
          ) ===
            String(
              req.user.schoolId
            )
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error:
          "Subject not found"
      });
    }

    if (req.body.name !== undefined) {
      list[index].name =
        clean(req.body.name);
    }

    if (req.body.code !== undefined) {
      list[index].code =
        clean(req.body.code);
    }

    if (
      req.body.description !==
      undefined
    ) {
      list[index].description =
        clean(
          req.body.description
        );
    }

    list[index].updatedAt =
      now();

    saveSubjects(list);

    res.json({
      ok: true,
      subject:
        list[index]
    });
  }
);

app.delete(
  "/api/subjects/:id",
  ...requireRole(
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    const list =
      subjects();

    const index =
      list.findIndex(
        item =>
          String(item.id) ===
            String(
              req.params.id
            ) &&
          String(
            item.schoolId
          ) ===
            String(
              req.user.schoolId
            )
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error:
          "Subject not found"
      });
    }

    list.splice(
      index,
      1
    );

    saveSubjects(list);

    res.json({
      ok: true,
      message:
        "Subject deleted"
    });
  }
);

// ============================================================
// CBT / EXAMS
// ============================================================

app.get(
  "/api/exams",
  ...requireRole(
    "school_admin",
    "teacher",
    "student"
  ),
  (req, res) => {
    let list =
      exams().filter(
        exam =>
          String(
            exam.schoolId
          ) ===
          String(
            req.user.schoolId
          )
      );

    if (
      req.query.subjectId
    ) {
      list =
        list.filter(
          exam =>
            String(
              exam.subjectId
            ) ===
            String(
              req.query.subjectId
            )
        );
    }

    res.json({
      ok: true,
      exams: list
    });
  }
);

app.post(
  "/api/exams",
  ...requireRole(
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    const {
      title,
      subjectId,
      description,
      duration,
      totalMarks,
      startTime,
      endTime,
      status,
      instructions
    } = req.body;

    if (
      !title ||
      !subjectId
    ) {
      return res.status(400).json({
        ok: false,
        error:
          "Title and subject are required"
      });
    }

    const subject =
      subjects().find(
        item =>
          String(item.id) ===
            String(subjectId) &&
          String(
            item.schoolId
          ) ===
            String(
              req.user.schoolId
            )
      );

    if (!subject) {
      return res.status(404).json({
        ok: false,
        error:
          "Subject not found"
      });
    }

    const list =
      exams();

    const exam = {
      id: id("exam"),
      schoolId:
        req.user.schoolId,
      subjectId:
        subjectId,
      title:
        clean(title),
      description:
        clean(description),
      instructions:
        clean(instructions),
      duration:
        Number(duration || 30),
      totalMarks:
        Number(totalMarks || 0),
      startTime:
        startTime || null,
      endTime:
        endTime || null,
      status:
        clean(status) ||
        "draft",
      createdBy:
        req.user.id,
      createdAt: now(),
      updatedAt: now()
    };

    list.push(exam);

    saveExams(list);

    res.status(201).json({
      ok: true,
      exam
    });
  }
);

app.put(
  "/api/exams/:id",
  ...requireRole(
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    const list =
      exams();

    const index =
      list.findIndex(
        exam =>
          String(exam.id) ===
            String(
              req.params.id
            ) &&
          String(
            exam.schoolId
          ) ===
            String(
              req.user.schoolId
            )
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error:
          "CBT not found"
      });
    }

    const exam =
      list[index];

    const fields = [
      "title",
      "description",
      "instructions",
      "duration",
      "totalMarks",
      "startTime",
      "endTime",
      "status"
    ];

    fields.forEach(
      field => {
        if (
          req.body[field] !==
          undefined
        ) {
          exam[field] =
            field ===
              "duration" ||
            field ===
              "totalMarks"
              ? Number(
                  req.body[field]
                )
              : req.body[field];
        }
      }
    );

    exam.updatedAt =
      now();

    list[index] =
      exam;

    saveExams(list);

    res.json({
      ok: true,
      exam
    });
  }
);

app.delete(
  "/api/exams/:id",
  ...requireRole(
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    const list =
      exams();

    const index =
      list.findIndex(
        exam =>
          String(exam.id) ===
            String(
              req.params.id
            ) &&
          String(
            exam.schoolId
          ) ===
            String(
              req.user.schoolId
            )
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error:
          "CBT not found"
      });
    }

    list.splice(
      index,
      1
    );

    saveExams(list);

    // Remove associated questions.
    const remainingQuestions =
      questions().filter(
        question =>
          String(
            question.examId
          ) !==
          String(
            req.params.id
          ) ||
          String(
            question.schoolId
          ) !==
            String(
              req.user.schoolId
            )
      );

    saveQuestions(
      remainingQuestions
    );

    res.json({
      ok: true,
      message:
        "CBT deleted"
    });
  }
);

// ============================================================
// QUESTION BANK
// ============================================================

app.get(
  "/api/questions",
  ...requireRole(
    "school_admin",
    "teacher",
    "student"
  ),
  (req, res) => {
    let list =
      questions().filter(
        question =>
          String(
            question.schoolId
          ) ===
          String(
            req.user.schoolId
          )
      );

    if (
      req.query.examId
    ) {
      list =
        list.filter(
          question =>
            String(
              question.examId
            ) ===
            String(
              req.query.examId
            )
        );
    }

    if (
      req.query.subjectId
    ) {
      const examIds =
        exams()
          .filter(
            exam =>
              String(
                exam.subjectId
              ) ===
              String(
                req.query.subjectId
              ) &&
              String(
                exam.schoolId
              ) ===
                String(
                  req.user.schoolId
                )
          )
          .map(
            exam =>
              String(exam.id)
          );

      list =
        list.filter(
          question =>
            examIds.includes(
              String(
                question.examId
              )
            )
        );
    }

    // Hide correct answers from students.
    if (
      req.user.role ===
      "student"
    ) {
      list =
        list.map(
          question => {
            const copy = {
              ...question
            };

            delete copy.answer;

            return copy;
          }
        );
    }

    res.json({
      ok: true,
      questions: list
    });
  }
);

// ============================================================
// ADD QUESTION
// ============================================================

app.post(
  "/api/questions",
  ...requireRole(
    "school_admin",
    "teacher"
  ),
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
          "Exam and question are required"
      });
    }

    const exam =
      exams().find(
        item =>
          String(item.id) ===
            String(examId) &&
          String(
            item.schoolId
          ) ===
            String(
              req.user.schoolId
            )
      );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        error:
          "CBT not found"
      });
    }

    const list =
      questions();

    const newQuestion = {
      id: id("question"),
      schoolId:
        req.user.schoolId,
      examId,
      question:
        clean(question),
      options:
        Array.isArray(options)
          ? options
          : [],
      answer:
        Number(
          answer ?? 0
        ),
      points:
        Number(points || 1),
      difficulty:
        clean(
          difficulty
        ) || "easy",
      tags:
        clean(tags),
      createdBy:
        req.user.id,
      createdAt: now(),
      updatedAt: now()
    };

    list.push(
      newQuestion
    );

    saveQuestions(list);

    res.status(201).json({
      ok: true,
      question:
        newQuestion
    });
  }
);

// ============================================================
// BULK QUESTION IMPORT
// ============================================================

app.post(
  "/api/questions/bulk",
  ...requireRole(
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    try {
      const {
        examId,
        questions: incoming
      } = req.body;

      if (
        !examId ||
        !Array.isArray(
          incoming
        )
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "examId and questions array are required"
        });
      }

      const exam =
        exams().find(
          item =>
            String(item.id) ===
              String(examId) &&
            String(
              item.schoolId
            ) ===
              String(
                req.user.schoolId
              )
        );

      if (!exam) {
        return res.status(404).json({
          ok: false,
          error:
            "CBT not found"
        });
      }

      const list =
        questions();

      const created =
        incoming.map(
          item => ({
            id: id("question"),
            schoolId:
              req.user.schoolId,
            examId,
            question:
              clean(
                item.question
              ),
            options:
              Array.isArray(
                item.options
              )
                ? item.options
                : [],
            answer:
              Number(
                item.answer ?? 0
              ),
            points:
              Number(
                item.points || 1
              ),
            difficulty:
              clean(
                item.difficulty
              ) || "easy",
            tags:
              clean(
                item.tags
              ),
            createdBy:
              req.user.id,
            createdAt: now(),
            updatedAt: now()
          })
        );

      list.push(
        ...created
      );

      saveQuestions(list);

      res.status(201).json({
        ok: true,
        message:
          `${created.length} questions imported`,
        count:
          created.length,
        questions:
          created
      });
    } catch (error) {
      console.error(
        "BULK QUESTION ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Could not import questions"
      });
    }
  }
);

// ============================================================
// UPDATE QUESTION
// ============================================================

app.put(
  "/api/questions/:id",
  ...requireRole(
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    const list =
      questions();

    const index =
      list.findIndex(
        question =>
          String(
            question.id
          ) ===
            String(
              req.params.id
            ) &&
          String(
            question.schoolId
          ) ===
            String(
              req.user.schoolId
            )
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error:
          "Question not found"
      });
    }

    const question =
      list[index];

    if (
      req.body.question !==
      undefined
    ) {
      question.question =
        clean(
          req.body.question
        );
    }

    if (
      req.body.options !==
      undefined
    ) {
      question.options =
        Array.isArray(
          req.body.options
        )
          ? req.body.options
          : [];
    }

    if (
      req.body.answer !==
      undefined
    ) {
      question.answer =
        Number(
          req.body.answer
        );
    }

    if (
      req.body.points !==
      undefined
    ) {
      question.points =
        Number(
          req.body.points
        );
    }

    if (
      req.body.difficulty !==
      undefined
    ) {
      question.difficulty =
        clean(
          req.body.difficulty
        );
    }

    if (
      req.body.tags !==
      undefined
    ) {
      question.tags =
        clean(
          req.body.tags
        );
    }

    question.updatedAt =
      now();

    list[index] =
      question;

    saveQuestions(list);

    res.json({
      ok: true,
      question
    });
  }
);

// ============================================================
// DELETE QUESTION
// ============================================================

app.delete(
  "/api/questions/:id",
  ...requireRole(
    "school_admin",
    "teacher"
  ),
  (req, res) => {
    const list =
      questions();

    const index =
      list.findIndex(
        question =>
          String(
            question.id
          ) ===
            String(
              req.params.id
            ) &&
          String(
            question.schoolId
          ) ===
            String(
              req.user.schoolId
            )
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error:
          "Question not found"
      });
    }

    list.splice(
      index,
      1
    );

    saveQuestions(list);

    res.json({
      ok: true,
      message:
        "Question deleted"
    });
  }
);

// ============================================================
// START CBT
// ============================================================

app.post(
  "/api/exams/:id/start",
  ...requireRole("student"),
  (req, res) => {
    const exam =
      exams().find(
        item =>
          String(item.id) ===
            String(
              req.params.id
            ) &&
          String(
            item.schoolId
          ) ===
            String(
              req.user.schoolId
            )
      );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        error:
          "CBT not found"
      });
    }

    const examQuestions =
      questions().filter(
        question =>
          String(
            question.examId
          ) ===
            String(exam.id) &&
          String(
            question.schoolId
          ) ===
            String(
              req.user.schoolId
            )
      );

    // Never send answers to student.
    const safeQuestions =
      examQuestions.map(
        question => ({
          id:
            question.id,
          examId:
            question.examId,
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
      exam,
      questions:
        safeQuestions
    });
  }
);

// ============================================================
// SUBMIT CBT
// ============================================================

app.post(
  "/api/exams/:id/submit",
  ...requireRole("student"),
  (req, res) => {
    const exam =
      exams().find(
        item =>
          String(item.id) ===
            String(
              req.params.id
            ) &&
          String(
            item.schoolId
          ) ===
            String(
              req.user.schoolId
            )
      );

    if (!exam) {
      return res.status(404).json({
        ok: false,
        error:
          "CBT not found"
      });
    }

    const examQuestions =
      questions().filter(
        question =>
          String(
            question.examId
          ) ===
            String(exam.id) &&
          String(
            question.schoolId
          ) ===
            String(
              req.user.schoolId
            )
      );

    const answers =
      req.body.answers ||
      {};

    let score = 0;

    let totalMarks = 0;

    let correct = 0;

    for (
      const question of
        examQuestions
    ) {
      const points =
        Number(
          question.points || 1
        );

      totalMarks +=
        points;

      const submitted =
        answers[
          question.id
        ];

      if (
        submitted !==
          undefined &&
        Number(
          submitted
        ) ===
          Number(
            question.answer
          )
      ) {
        score += points;
        correct++;
      }
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

    const list =
      results();

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
      correct,
      totalQuestions:
        examQuestions.length,
      answers,
      submittedAt:
        now()
    };

    list.push(result);

    saveResults(list);

    res.json({
      ok: true,
      message:
        "CBT submitted successfully",
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
    let list =
      results().filter(
        result =>
          String(
            result.schoolId
          ) ===
          String(
            req.user.schoolId
          )
      );

    if (
      req.user.role ===
      "student"
    ) {
      list =
        list.filter(
          result =>
            String(
              result.studentId
            ) ===
            String(
              req.user.id
            )
        );
    }

    res.json({
      ok: true,
      results: list
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
    const list =
      announcements().filter(
        item =>
          String(
            item.schoolId
          ) ===
          String(
            req.user.schoolId
          )
      );

    res.json({
      ok: true,
      announcements:
        list
    });
  }
);

app.post(
  "/api/announcements",
  ...requireRole(
    "school_admin",
    "teacher"
  ),
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
          "Title and message are required"
      });
    }

    const list =
      announcements();

    const announcement = {
      id:
        id("announcement"),
      schoolId:
        req.user.schoolId,
      title:
        clean(title),
      message:
        clean(message),
      createdBy:
        req.user.id,
      createdAt: now(),
      updatedAt: now()
    };

    list.push(
      announcement
    );

    saveAnnouncements(
      list
    );

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
    const schoolId =
      req.user.schoolId;

    const schoolUsers =
      users().filter(
        user =>
          String(
            user.schoolId
          ) ===
          String(schoolId)
      );

    const schoolSubjects =
      subjects().filter(
        subject =>
          String(
            subject.schoolId
          ) ===
          String(schoolId)
      );

    const schoolExams =
      exams().filter(
        exam =>
          String(
            exam.schoolId
          ) ===
          String(schoolId)
      );

    const schoolQuestions =
      questions().filter(
        question =>
          String(
            question.schoolId
          ) ===
          String(schoolId)
      );

    const schoolResults =
      results().filter(
        result =>
          String(
            result.schoolId
          ) ===
          String(schoolId)
      );

    res.json({
      ok: true,
      summary: {
        students:
          schoolUsers.filter(
            user =>
              user.role ===
              "student"
          ).length,

        teachers:
          schoolUsers.filter(
            user =>
              user.role ===
              "teacher"
          ).length,

        subjects:
          schoolSubjects.length,

        exams:
          schoolExams.length,

        questions:
          schoolQuestions.length,

        results:
          schoolResults.length
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
    const schoolId =
      req.user.schoolId;

    res.json({
      ok: true,
      summary: {
        subjects:
          subjects().filter(
            item =>
              String(
                item.schoolId
              ) ===
              String(
                schoolId
              )
          ).length,

        exams:
          exams().filter(
            item =>
              String(
                item.schoolId
              ) ===
              String(
                schoolId
              )
          ).length,

        questions:
          questions().filter(
            item =>
              String(
                item.schoolId
              ) ===
              String(
                schoolId
              )
          ).length,

        students:
          users().filter(
            item =>
              String(
                item.schoolId
              ) ===
                String(
                  schoolId
                ) &&
              item.role ===
                "student"
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
  ...requireRole("student"),
  (req, res) => {
    const schoolId =
      req.user.schoolId;

    res.json({
      ok: true,
      summary: {
        exams:
          exams().filter(
            exam =>
              String(
                exam.schoolId
              ) ===
              String(
                schoolId
              )
          ).length,

        completedExams:
          results().filter(
            result =>
              String(
                result.studentId
              ) ===
              String(
                req.user.id
              )
          ).length,

        announcements:
          announcements().filter(
            announcement =>
              String(
                announcement.schoolId
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
// SUPERADMIN SCHOOLS
// ============================================================

app.get(
  "/api/admin/schools",
  ...requireRole("superadmin"),
  (req, res) => {
    const allSchools =
      schools();

    const allUsers =
      users();

    const enriched =
      allSchools.map(
        school => ({
          ...school,

          userCount:
            allUsers.filter(
              user =>
                String(
                  user.schoolId
                ) ===
                String(
                  school.id
                )
            ).length,

          students:
            allUsers.filter(
              user =>
                String(
                  user.schoolId
                ) ===
                  String(
                    school.id
                  ) &&
                user.role ===
                  "student"
            ).length,

          teachers:
            allUsers.filter(
              user =>
                String(
                  user.schoolId
                ) ===
                  String(
                    school.id
                  ) &&
                user.role ===
                  "teacher"
            ).length
        })
      );

    res.json({
      ok: true,
      schools:
        enriched
    });
  }
);

// ============================================================
// SUPERADMIN CREATE SCHOOL
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
            "School and admin details are required"
        });
      }

      const allUsers =
        users();

      const adminEmailNormalized =
        email(adminEmail);

      const adminUsernameNormalized =
        username(
          adminUsername
        );

      if (
        allUsers.some(
          user =>
            email(
              user.email
            ) ===
            adminEmailNormalized
        )
      ) {
        return res.status(409).json({
          ok: false,
          error:
            "Admin email already exists"
        });
      }

      if (
        allUsers.some(
          user =>
            username(
              user.username
            ) ===
            adminUsernameNormalized
        )
      ) {
        return res.status(409).json({
          ok: false,
          error:
            "Admin username already exists"
        });
      }

      const school = {
        id: id("school"),
        name:
          clean(name),
        motto:
          clean(motto),
        logo: "",
        primaryColor:
          "#2563eb",
        secondaryColor:
          "#16a34a",
        theme:
          "light",
        active: true,
        createdAt: now(),
        updatedAt: now()
      };

      const allSchools =
        schools();

      allSchools.push(
        school
      );

      saveSchools(
        allSchools
      );

      const passwordHash =
        await bcrypt.hash(
          String(
            adminPassword
          ),
          12
        );

      const admin = {
        id:
          id("user"),
        fullName:
          clean(adminName),
        username:
          adminUsernameNormalized,
        email:
          adminEmailNormalized,
        passwordHash,
        role:
          "school_admin",
        schoolId:
          school.id,
        profilePicture: "",
        provider:
          "local",
        active: true,
        createdAt: now(),
        updatedAt: now()
      };

      allUsers.push(
        admin
      );

      saveUsers(
        allUsers
      );

      res.status(201).json({
        ok: true,
        school,
        admin:
          safeUser(admin)
      });
    } catch (error) {
      console.error(
        "SUPERADMIN SCHOOL ERROR:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Could not create school"
      });
    }
  }
);

// ============================================================
// SUPERADMIN UPDATE SCHOOL
// ============================================================

app.put(
  "/api/admin/schools/:id",
  ...requireRole("superadmin"),
  (req, res) => {
    const allSchools =
      schools();

    const index =
      allSchools.findIndex(
        school =>
          String(
            school.id
          ) ===
          String(
            req.params.id
          )
      );

    if (index === -1) {
      return res.status(404).json({
        ok: false,
        error:
          "School not found"
      });
    }

    const school =
      allSchools[index];

    [
      "name",
      "motto",
      "logo",
      "primaryColor",
      "secondaryColor",
      "theme"
    ].forEach(
      field => {
        if (
          req.body[field] !==
          undefined
        ) {
          school[field] =
            req.body[field];
        }
      }
    );

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

    allSchools[index] =
      school;

    saveSchools(
      allSchools
    );

    res.json({
      ok: true,
      school
    });
  }
);

// ============================================================
// SUPERADMIN USERS
// ============================================================

app.get(
  "/api/admin/users",
  ...requireRole("superadmin"),
  (req, res) => {
    const allUsers =
      users();

    const allSchools =
      schools();

    const list =
      allUsers.map(
        user => ({
          ...safeUser(
            user
          ),

          schoolName:
            allSchools.find(
              school =>
                String(
                  school.id
                ) ===
                String(
                  user.schoolId
                )
            )?.name ||
            null
        })
      );

    res.json({
      ok: true,
      users: list
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
    const allUsers =
      users();

    const allSchools =
      schools();

    res.json({
      ok: true,
      summary: {
        schools:
          allSchools.length,

        activeSchools:
          allSchools.filter(
            school =>
              school.active !==
              false
          ).length,

        users:
          allUsers.length,

        schoolAdmins:
          allUsers.filter(
            user =>
              user.role ===
              "school_admin"
          ).length,

        teachers:
          allUsers.filter(
            user =>
              user.role ===
              "teacher"
          ).length,

        students:
          allUsers.filter(
            user =>
              user.role ===
              "student"
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
    const config =
      settings();

    const allowed = [
      "platformName",
      "platformDescription",
      "defaultTheme",
      "maintenanceMode",
      "primaryColor",
      "secondaryColor"
    ];

    allowed.forEach(
      field => {
        if (
          req.body[field] !==
          undefined
        ) {
          config[field] =
            req.body[field];
        }
      }
    );

    saveSettings(
      config
    );

    res.json({
      ok: true,
      settings:
        config
    });
  }
);

// ============================================================
// SUPERADMIN ENSURE
// ============================================================

async function ensureSuperadmin() {
  const superEmail =
    email(
      process.env.SUPERADMIN_EMAIL
    );

  const superUsername =
    username(
      process.env.SUPERADMIN_USERNAME ||
        "superadmin"
    );

  const superPassword =
    process.env.SUPERADMIN_PASSWORD;

  const superName =
    process.env.SUPERADMIN_NAME ||
    "SchoolHub Super Admin";

  if (
    !superEmail ||
    !superPassword
  ) {
    console.log(
      "SUPERADMIN: Environment variables not configured."
    );

    return;
  }

  const allUsers =
    users();

  let user =
    allUsers.find(
      item =>
        email(
          item.email
        ) ===
        superEmail
    ) ||
    allUsers.find(
      item =>
        username(
          item.username
        ) ===
        superUsername
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

    saveUsers(
      allUsers
    );

    console.log(
      `SUPERADMIN: ${user.email} ready`
    );

    return;
  }

  const passwordHash =
    await bcrypt.hash(
      superPassword,
      12
    );

  user = {
    id:
      id("user"),
    fullName:
      superName,
    username:
      superUsername,
    email:
      superEmail,
    passwordHash,
    role:
      "superadmin",
    schoolId:
      null,
    profilePicture: "",
    provider:
      "local",
    active:
      true,
    createdAt:
      now(),
    updatedAt:
      now()
  };

  allUsers.push(
    user
  );

  saveUsers(
    allUsers
  );

  console.log(
    `SUPERADMIN: Created ${superEmail}`
  );
}

// ============================================================
// DASHBOARD ROUTE
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
        dashboardFor(
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
// STATIC FILES
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
// PROTECTED DASHBOARD FILES
// ============================================================

app.get(
  "/superadmin.html",
  (req, res) => {
    if (
      !req.isAuthenticated ||
      !req.isAuthenticated() ||
      !req.user
    ) {
      return res.redirect(
        "/login.html"
      );
    }

    if (
      req.user.role !==
      "superadmin"
    ) {
      return res.redirect(
        dashboardFor(
          req.user
        )
      );
    }

    res.sendFile(
      path.join(
        PUBLIC_DIR,
        "superadmin.html"
      )
    );
  }
);

app.get(
  "/admin.html",
  (req, res) => {
    if (
      !req.isAuthenticated ||
      !req.isAuthenticated() ||
      !req.user
    ) {
      return res.redirect(
        "/login.html"
      );
    }

    if (
      req.user.role !==
      "school_admin"
    ) {
      return res.redirect(
        dashboardFor(
          req.user
        )
      );
    }

    res.sendFile(
      path.join(
        PUBLIC_DIR,
        "admin.html"
      )
    );
  }
);

app.get(
  "/teacher.html",
  (req, res) => {
    if (
      !req.isAuthenticated ||
      !req.isAuthenticated() ||
      !req.user
    ) {
      return res.redirect(
        "/login.html"
      );
    }

    if (
      req.user.role !==
      "teacher"
    ) {
      return res.redirect(
        dashboardFor(
          req.user
        )
      );
    }

    res.sendFile(
      path.join(
        PUBLIC_DIR,
        "teacher.html"
      )
    );
  }
);

app.get(
  "/student.html",
  (req, res) => {
    if (
      !req.isAuthenticated ||
      !req.isAuthenticated() ||
      !req.user
    ) {
      return res.redirect(
        "/login.html"
      );
    }

    if (
      req.user.role !==
      "student"
    ) {
      return res.redirect(
        dashboardFor(
          req.user
        )
      );
    }

    res.sendFile(
      path.join(
        PUBLIC_DIR,
        "student.html"
      )
    );
  }
);

// ============================================================
// 404
// ============================================================

app.use(
  (req, res) => {
    if (
      req.path.startsWith(
        "/api/"
      )
    ) {
      return res.status(404).json({
        ok: false,
        error:
          "API route not found"
      });
    }

    res.status(404).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>SchoolHub Pro - 404</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
      </head>
      <body style="
        font-family:Arial;
        display:flex;
        align-items:center;
        justify-content:center;
        min-height:100vh;
        margin:0;
        background:#f5f7fb;
      ">
        <div style="
          background:white;
          padding:40px;
          border-radius:20px;
          text-align:center;
          box-shadow:0 15px 50px rgba(0,0,0,.08);
        ">
          <h1>404</h1>
          <p>Page not found.</p>
          <a href="/login.html">
            Go to Login
          </a>
        </div>
      </body>
      </html>
    `);
  }
);

// ============================================================
// ERROR HANDLER
// ============================================================

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
      return next(error);
    }

    res.status(500).json({
      ok: false,
      error:
        error.message ||
        "Internal server error"
    });
  }
);

// ============================================================
// GRACEFUL SHUTDOWN
// ============================================================

let server = null;

function shutdown(signal) {
  console.log(
    `${signal} received. Shutting down...`
  );

  if (!server) {
    process.exit(0);
  }

  server.close(
    () => {
      console.log(
        "SchoolHub server closed."
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
// START
// ============================================================

async function start() {
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
            "          SCHOOLHUB PRO"
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
              GOOGLE_CONFIGURED
                ? "CONFIGURED"
                : "NOT CONFIGURED"
            }`
          );
          console.log(
            `Uploads: ${UPLOADS_DIR}`
          );
          console.log(
            "Multi-school: ENABLED"
          );
          console.log(
            "CBT: ENABLED"
          );
          console.log(
            "Question Bank: ENABLED"
          );
          console.log(
            "Branding: ENABLED"
          );
          console.log(
            "Profile Pictures: ENABLED"
          );
          console.log(
            "=========================================="
          );
          console.log("");
        }
      );
  } catch (error) {
    console.error(
      "START ERROR:",
      error
    );

    process.exit(1);
  }
}

start();
