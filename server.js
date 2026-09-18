/*
===========================================================
 SCHOOLHUB PRO
 MAIN SERVER
 Multi-School School Management + CBT Platform
 Railway + JSON Storage + Google OAuth
===========================================================
*/

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const dotenv = require("dotenv");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

dotenv.config();

const app = express();

/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;

app.set("trust proxy", 1);

const STORAGE_ROOT =
  process.env.STORAGE_ROOT || path.join(ROOT, "storage");

const DATA_DIR = path.join(STORAGE_ROOT, "data");
const UPLOADS_DIR = path.join(STORAGE_ROOT, "uploads");
const PROFILE_DIR = path.join(UPLOADS_DIR, "profiles");
const SCHOOL_UPLOAD_DIR = path.join(UPLOADS_DIR, "schools");

[
  STORAGE_ROOT,
  DATA_DIR,
  UPLOADS_DIR,
  PROFILE_DIR,
  SCHOOL_UPLOAD_DIR
].forEach((dir) => {
  fs.mkdirSync(dir, { recursive: true });
});

/* =========================================================
   DATABASE FILES
========================================================= */

const FILES = {
  users: path.join(DATA_DIR, "users.json"),
  schools: path.join(DATA_DIR, "schools.json"),
  subjects: path.join(DATA_DIR, "subjects.json"),
  announcements: path.join(DATA_DIR, "announcements.json"),
  exams: path.join(DATA_DIR, "exams.json"),
  questions: path.join(DATA_DIR, "questions.json"),
  results: path.join(DATA_DIR, "results.json"),
  attempts: path.join(DATA_DIR, "attempts.json"),
  cheatEvents: path.join(DATA_DIR, "cheat_events.json")
};

const DEFAULTS = {
  users: [],
  schools: [],
  subjects: [],
  announcements: [],
  exams: [],
  questions: [],
  results: [],
  attempts: [],
  cheatEvents: []
};

/* =========================================================
   JSON STORAGE
========================================================= */

function read(name) {
  const file = FILES[name];

  if (!file) {
    throw new Error(`Unknown data file: ${name}`);
  }

  try {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(
        file,
        JSON.stringify(DEFAULTS[name] || [], null, 2),
        "utf8"
      );
      return DEFAULTS[name] || [];
    }

    const raw = fs.readFileSync(file, "utf8").trim();

    if (!raw) {
      return [];
    }

    const parsed = JSON.parse(raw);

    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    console.error(`Failed reading ${name}.json:`, error.message);
    return [];
  }
}

function write(name, data) {
  const file = FILES[name];
  const temp = `${file}.tmp`;

  fs.writeFileSync(
    temp,
    JSON.stringify(data, null, 2),
    "utf8"
  );

  fs.renameSync(temp, file);
}

/* Initialize files */

Object.keys(FILES).forEach((name) => {
  if (!fs.existsSync(FILES[name])) {
    write(name, DEFAULTS[name] || []);
  }
});

/* =========================================================
   HELPERS
========================================================= */

function uid(prefix = "") {
  return (
    prefix +
    crypto.randomBytes(12).toString("hex")
  );
}

function now() {
  return new Date().toISOString();
}

function clean(value, max = 500) {
  if (value === undefined || value === null) return "";
  return String(value).trim().slice(0, max);
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
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
    active: user.active !== false,
    provider: user.provider || "local",
    createdAt: user.createdAt
  };
}

function getUser(id) {
  return read("users").find((u) => u.id === id);
}

function getSchool(id) {
  return read("schools").find((s) => s.id === id);
}

function getSubject(id) {
  return read("subjects").find((s) => s.id === id);
}

function getExam(id) {
  return read("exams").find((e) => e.id === id);
}

function getQuestion(id) {
  return read("questions").find((q) => q.id === id);
}

function getAttempt(id) {
  return read("attempts").find((a) => a.id === id);
}

function schoolAllowed(user, schoolId) {
  if (!user) return false;

  if (user.role === "superadmin") {
    return true;
  }

  return String(user.schoolId) === String(schoolId);
}

function roleAllowed(user, roles) {
  return roles.includes(user.role);
}

/* =========================================================
   EXPRESS MIDDLEWARE
========================================================= */

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

/* =========================================================
   SESSION
========================================================= */

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "schoolhub-development-secret-change-this";

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000
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
  const user = getUser(id);
  done(null, user || false);
});

/* =========================================================
   GOOGLE AUTH
========================================================= */

const googleConfigured =
  !!process.env.GOOGLE_CLIENT_ID &&
  !!process.env.GOOGLE_CLIENT_SECRET &&
  !!process.env.GOOGLE_CALLBACK_URL;

if (googleConfigured) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL
      },

      async (accessToken, refreshToken, profile, done) => {
        try {
          const users = read("users");

          const email =
            profile.emails &&
            profile.emails[0]
              ? profile.emails[0].value.toLowerCase()
              : "";

          const googleId = profile.id;

          let user =
            users.find(
              (u) =>
                u.providerId === googleId ||
                (email &&
                  u.email &&
                  u.email.toLowerCase() === email)
            );

          if (!user) {
            /*
              Security decision:
              Google login does NOT automatically create
              a school/admin account.

              The user must already have a SchoolHub account.
            */
            return done(
              null,
              false,
              {
                message:
                  "No SchoolHub account was found for this Google account."
              }
            );
          }

          if (user.active === false) {
            return done(
              null,
              false,
              {
                message: "This account is inactive."
              }
            );
          }

          user.provider = "google";
          user.providerId = googleId;

          if (
            profile.photos &&
            profile.photos[0] &&
            !user.profilePicture
          ) {
            user.profilePicture = profile.photos[0].value;
          }

          write("users", users);

          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );
}

/* =========================================================
   MULTER
========================================================= */

const imageStorage = multer.diskStorage({
  destination(req, file, cb) {
    if (req.path.includes("/school/logo")) {
      cb(null, SCHOOL_UPLOAD_DIR);
    } else {
      cb(null, PROFILE_DIR);
    }
  },

  filename(req, file, cb) {
    const ext =
      path.extname(file.originalname).toLowerCase() || ".jpg";

    cb(
      null,
      `${Date.now()}-${crypto
        .randomBytes(6)
        .toString("hex")}${ext}`
    );
  }
});

const imageUpload = multer({
  storage: imageStorage,

  limits: {
    fileSize: 5 * 1024 * 1024
  },

  fileFilter(req, file, cb) {
    const allowed = [
      "image/jpeg",
      "image/png",
      "image/webp"
    ];

    if (!allowed.includes(file.mimetype)) {
      return cb(
        new Error("Only JPG, PNG and WEBP images are allowed.")
      );
    }

    cb(null, true);
  }
});

/* =========================================================
   STATIC FILES
========================================================= */

app.use(
  "/uploads",
  express.static(UPLOADS_DIR)
);

app.use(
  express.static(path.join(ROOT, "public"))
);

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function auth(req, res, next) {
  const userId = req.session.userId;

  if (!userId) {
    return res.status(401).json({
      error: "Authentication required"
    });
  }

  const user = getUser(userId);

  if (!user) {
    req.session.destroy(() => {});
    return res.status(401).json({
      error: "Session expired"
    });
  }

  if (user.active === false) {
    req.session.destroy(() => {});
    return res.status(403).json({
      error: "Account is inactive"
    });
  }

  req.user = user;

  next();
}

function requireRoles(...roles) {
  return [
    auth,
    (req, res, next) => {
      if (!roles.includes(req.user.role)) {
        return res.status(403).json({
          error: "Access denied"
        });
      }

      next();
    }
  ];
}

function sendLoginRedirect(res, role) {
  if (
    role === "superadmin" ||
    role === "school_admin"
  ) {
    return res.json({
      success: true,
      redirect: "/admin.html"
    });
  }

  if (role === "teacher") {
    return res.json({
      success: true,
      redirect: "/teacher.html"
    });
  }

  if (role === "student") {
    return res.json({
      success: true,
      redirect: "/student.html"
    });
  }

  return res.json({
    success: true,
    redirect: "/login.html"
  });
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "ok",
    app: "SchoolHub Pro",
    version: "4.0.0",
    timestamp: now(),
    storage: STORAGE_ROOT,
    googleAuth: googleConfigured
      ? "CONFIGURED"
      : "NOT CONFIGURED"
  });
});

/* =========================================================
   PLATFORM
========================================================= */

app.get("/api/platform-config", (req, res) => {
  res.json({
    platformName: "SchoolHub Pro",
    description:
      "Smart multi-school management and CBT platform.",
    googleAuth: googleConfigured
  });
});

/* =========================================================
   CURRENT USER
========================================================= */

app.get("/api/me", auth, (req, res) => {
  const school = req.user.schoolId
    ? getSchool(req.user.schoolId)
    : null;

  res.json({
    user: safeUser(req.user),
    school: school || null
  });
});

/* =========================================================
   REGISTER SCHOOL + ADMIN
========================================================= */

app.post("/api/register", async (req, res) => {
  try {
    const schoolName = clean(
      req.body.schoolName || req.body.name,
      120
    );

    const motto = clean(req.body.motto, 200);
    const fullName = clean(req.body.fullName, 100);
    const username = clean(req.body.username, 50);
    const email = clean(req.body.email, 150).toLowerCase();
    const password = String(req.body.password || "");

    if (
      !schoolName ||
      !fullName ||
      !username ||
      !email ||
      !password
    ) {
      return res.status(400).json({
        error: "Please complete all required fields."
      });
    }

    if (!validEmail(email)) {
      return res.status(400).json({
        error: "Please enter a valid email address."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must contain at least 6 characters."
      });
    }

    const users = read("users");
    const schools = read("schools");

    if (
      users.some(
        (u) =>
          u.username.toLowerCase() === username.toLowerCase()
      )
    ) {
      return res.status(409).json({
        error: "Username already exists."
      });
    }

    if (
      users.some(
        (u) =>
          u.email &&
          u.email.toLowerCase() === email
      )
    ) {
      return res.status(409).json({
        error: "Email already exists."
      });
    }

    const schoolId = uid("school_");

    const school = {
      id: schoolId,
      name: schoolName,
      motto,
      logo: "",
      primaryColor: "#2563eb",
      secondaryColor: "#16a34a",
      theme: "light",
      active: true,
      createdAt: now()
    };

    const user = {
      id: uid("user_"),
      fullName,
      username,
      email,
      passwordHash: await bcrypt.hash(password, 12),
      role: "school_admin",
      schoolId,
      profilePicture: "",
      active: true,
      provider: "local",
      createdAt: now()
    };

    schools.push(school);
    users.push(user);

    write("schools", schools);
    write("users", users);

    req.session.userId = user.id;

    return res.json({
      success: true,
      redirect: "/admin.html",
      user: safeUser(user),
      school
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      error: "Registration failed."
    });
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {
  try {
    const identifier = clean(
      req.body.identifier ||
      req.body.username ||
      req.body.email,
      150
    );

    const password = String(req.body.password || "");

    if (!identifier || !password) {
      return res.status(400).json({
        error: "Username/email and password are required."
      });
    }

    const users = read("users");

    const user = users.find((u) => {
      const username =
        String(u.username || "").toLowerCase();

      const email =
        String(u.email || "").toLowerCase();

      return (
        username === identifier.toLowerCase() ||
        email === identifier.toLowerCase()
      );
    });

    if (!user) {
      return res.status(401).json({
        error: "Invalid login details."
      });
    }

    if (user.active === false) {
      return res.status(403).json({
        error: "Your account is inactive."
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.passwordHash || ""
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid login details."
      });
    }

    req.session.userId = user.id;

    return sendLoginRedirect(
      res,
      user.role
    );
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      error: "An internal error occurred during login."
    });
  }
});

/* =========================================================
   LOGOUT
========================================================= */

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");

    res.json({
      success: true
    });
  });
});

/* =========================================================
   GOOGLE LOGIN
========================================================= */

app.get("/auth/google", (req, res, next) => {
  if (!googleConfigured) {
    return res.redirect(
      "/login.html?error=Google%20Sign-In%20is%20not%20configured"
    );
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
        "/login.html?error=Google%20Sign-In%20is%20not%20configured"
      );
    }

    passport.authenticate(
      "google",
      {
        failureRedirect:
          "/login.html?error=Google%20authentication%20failed"
      },
      (err, user, info) => {
        if (err) {
          console.error(
            "GOOGLE CALLBACK ERROR:",
            err
          );

          return res.redirect(
            "/login.html?error=Google%20authentication%20failed"
          );
        }

        if (!user) {
          const message =
            info && info.message
              ? info.message
              : "Google authentication failed.";

          return res.redirect(
            "/login.html?error=" +
              encodeURIComponent(message)
          );
        }

        req.login(user, (loginError) => {
          if (loginError) {
            console.error(
              "GOOGLE SESSION ERROR:",
              loginError
            );

            return res.redirect(
              "/login.html?error=Could%20not%20create%20session"
            );
          }

          req.session.userId = user.id;

          if (
            user.role === "superadmin" ||
            user.role === "school_admin"
          ) {
            return res.redirect("/admin.html");
          }

          if (user.role === "teacher") {
            return res.redirect("/teacher.html");
          }

          if (user.role === "student") {
            return res.redirect("/student.html");
          }

          return res.redirect("/login.html");
        });
      }
    )(req, res, next);
  }
);

/* =========================================================
   SCHOOL
========================================================= */

app.get("/api/school", auth, (req, res) => {
  if (!req.user.schoolId) {
    return res.json({
      school: null
    });
  }

  const school = getSchool(req.user.schoolId);

  res.json({
    school: school || null
  });
});

/* =========================================================
   SCHOOL BRANDING
========================================================= */

app.put(
  "/api/school/branding",
  ...requireRoles(
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    const schoolId =
      req.user.role === "superadmin"
        ? clean(req.body.schoolId)
        : req.user.schoolId;

    if (!schoolId) {
      return res.status(400).json({
        error: "School ID is required."
      });
    }

    const schools = read("schools");

    const school = schools.find(
      (s) => s.id === schoolId
    );

    if (!school) {
      return res.status(404).json({
        error: "School not found."
      });
    }

    school.name =
      clean(req.body.name, 120) ||
      school.name;

    school.motto =
      clean(req.body.motto, 200);

    school.primaryColor =
      clean(req.body.primaryColor, 30) ||
      school.primaryColor;

    school.secondaryColor =
      clean(req.body.secondaryColor, 30) ||
      school.secondaryColor;

    school.theme =
      ["light", "dark", "system"].includes(
        req.body.theme
      )
        ? req.body.theme
        : school.theme;

    write("schools", schools);

    res.json({
      success: true,
      school
    });
  }
);

/* =========================================================
   SCHOOL LOGO
========================================================= */

app.post(
  "/api/school/logo",
  ...requireRoles(
    "school_admin",
    "superadmin"
  ),
  imageUpload.single("logo"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        error: "Logo image is required."
      });
    }

    const schoolId =
      req.user.role === "superadmin"
        ? clean(req.body.schoolId)
        : req.user.schoolId;

    const schools = read("schools");

    const school = schools.find(
      (s) => s.id === schoolId
    );

    if (!school) {
      return res.status(404).json({
        error: "School not found."
      });
    }

    school.logo =
      `/uploads/schools/${req.file.filename}`;

    write("schools", schools);

    res.json({
      success: true,
      school
    });
  }
);

/* =========================================================
   PROFILE PICTURE
========================================================= */

app.post(
  "/api/profile-picture",
  auth,
  imageUpload.single("profilePicture"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        error: "Profile picture is required."
      });
    }

    const users = read("users");

    const user = users.find(
      (u) => u.id === req.user.id
    );

    if (!user) {
      return res.status(404).json({
        error: "User not found."
      });
    }

    user.profilePicture =
      `/uploads/profiles/${req.file.filename}`;

    write("users", users);

    res.json({
      success: true,
      user: safeUser(user)
    });
  }
);

/* =========================================================
   USERS
========================================================= */

app.get(
  "/api/users",
  ...requireRoles(
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    let users = read("users");

    if (req.user.role !== "superadmin") {
      users = users.filter(
        (u) =>
          u.schoolId === req.user.schoolId
      );
    }

    res.json({
      users: users.map(safeUser)
    });
  }
);

app.post(
  "/api/users",
  ...requireRoles(
    "school_admin",
    "superadmin"
  ),
  async (req, res) => {
    try {
      const users = read("users");

      const fullName = clean(
        req.body.fullName,
        100
      );

      const username = clean(
        req.body.username,
        50
      );

      const email = clean(
        req.body.email,
        150
      ).toLowerCase();

      const password = String(
        req.body.password || ""
      );

      const role = clean(
        req.body.role,
        30
      );

      let schoolId =
        req.user.role === "superadmin"
          ? clean(req.body.schoolId)
          : req.user.schoolId;

      if (!schoolId) {
        return res.status(400).json({
          error: "School is required."
        });
      }

      if (
        !["teacher", "student", "school_admin"].includes(
          role
        )
      ) {
        return res.status(400).json({
          error:
            "Allowed roles: teacher, student, school_admin."
        });
      }

      if (
        req.user.role !== "superadmin" &&
        role === "school_admin"
      ) {
        return res.status(403).json({
          error:
            "School admins cannot create another school admin."
        });
      }

      if (!fullName || !username || !email) {
        return res.status(400).json({
          error: "Name, username and email are required."
        });
      }

      if (!validEmail(email)) {
        return res.status(400).json({
          error: "Invalid email address."
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error:
            "Password must contain at least 6 characters."
        });
      }

      if (
        users.some(
          (u) =>
            String(u.username).toLowerCase() ===
            username.toLowerCase()
        )
      ) {
        return res.status(409).json({
          error: "Username already exists."
        });
      }

      if (
        users.some(
          (u) =>
            String(u.email).toLowerCase() ===
            email
        )
      ) {
        return res.status(409).json({
          error: "Email already exists."
        });
      }

      if (!getSchool(schoolId)) {
        return res.status(404).json({
          error: "School not found."
        });
      }

      const user = {
        id: uid("user_"),
        fullName,
        username,
        email,
        passwordHash:
          await bcrypt.hash(password, 12),
        role,
        schoolId,
        profilePicture: "",
        active: true,
        provider: "local",
        createdAt: now()
      };

      users.push(user);
      write("users", users);

      res.json({
        success: true,
        user: safeUser(user)
      });
    } catch (error) {
      console.error("CREATE USER ERROR:", error);

      res.status(500).json({
        error: "Could not create user."
      });
    }
  }
);

/* =========================================================
   UPDATE USER
========================================================= */

app.put(
  "/api/users/:id",
  ...requireRoles(
    "school_admin",
    "superadmin"
  ),
  async (req, res) => {
    try {
      const users = read("users");

      const user = users.find(
        (u) => u.id === req.params.id
      );

      if (!user) {
        return res.status(404).json({
          error: "User not found."
        });
      }

      if (
        req.user.role !== "superadmin" &&
        user.schoolId !== req.user.schoolId
      ) {
        return res.status(403).json({
          error: "Access denied."
        });
      }

      if (req.body.fullName !== undefined) {
        user.fullName = clean(
          req.body.fullName,
          100
        );
      }

      if (req.body.username !== undefined) {
        user.username = clean(
          req.body.username,
          50
        );
      }

      if (req.body.email !== undefined) {
        user.email = clean(
          req.body.email,
          150
        ).toLowerCase();
      }

      if (req.body.active !== undefined) {
        user.active = Boolean(
          req.body.active
        );
      }

      if (
        req.body.role &&
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

      if (req.body.password) {
        user.passwordHash =
          await bcrypt.hash(
            String(req.body.password),
            12
          );
      }

      write("users", users);

      res.json({
        success: true,
        user: safeUser(user)
      });
    } catch (error) {
      console.error("UPDATE USER ERROR:", error);

      res.status(500).json({
        error: "Could not update user."
      });
    }
  }
);

/* =========================================================
   DELETE USER
========================================================= */

app.delete(
  "/api/users/:id",
  ...requireRoles(
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    const users = read("users");

    const index = users.findIndex(
      (u) => u.id === req.params.id
    );

    if (index === -1) {
      return res.status(404).json({
        error: "User not found."
      });
    }

    const user = users[index];

    if (
      req.user.role !== "superadmin" &&
      user.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    if (user.id === req.user.id) {
      return res.status(400).json({
        error: "You cannot delete your own account."
      });
    }

    users.splice(index, 1);

    write("users", users);

    res.json({
      success: true
    });
  }
);

/* =========================================================
   ADMIN SUMMARY
========================================================= */

app.get(
  "/api/admin/summary",
  ...requireRoles(
    "school_admin",
    "superadmin"
  ),
  (req, res) => {
    let users = read("users");
    let schools = read("schools");
    let subjects = read("subjects");
    let exams = read("exams");
    let results = read("results");

    if (req.user.role !== "superadmin") {
      users = users.filter(
        (u) =>
          u.schoolId === req.user.schoolId
      );

      subjects = subjects.filter(
        (s) =>
          s.schoolId === req.user.schoolId
      );

      exams = exams.filter(
        (e) =>
          e.schoolId === req.user.schoolId
      );

      results = results.filter(
        (r) =>
          r.schoolId === req.user.schoolId
      );

      schools = schools.filter(
        (s) =>
          s.id === req.user.schoolId
      );
    }

    res.json({
      students: users.filter(
        (u) => u.role === "student"
      ).length,

      teachers: users.filter(
        (u) => u.role === "teacher"
      ).length,

      admins: users.filter(
        (u) =>
          u.role === "school_admin" ||
          u.role === "superadmin"
      ).length,

      schools: schools.length,
      subjects: subjects.length,
      exams: exams.length,
      results: results.length,
      users: users.length
    });
  }
);

/* =========================================================
   TEACHER SUMMARY
========================================================= */

app.get(
  "/api/teacher/summary",
  ...requireRoles("teacher"),
  (req, res) => {
    const schoolId = req.user.schoolId;

    const exams = read("exams").filter(
      (e) => e.schoolId === schoolId
    );

    const subjects = read("subjects").filter(
      (s) => s.schoolId === schoolId
    );

    const results = read("results").filter(
      (r) => r.schoolId === schoolId
    );

    const students = read("users").filter(
      (u) =>
        u.schoolId === schoolId &&
        u.role === "student"
    );

    res.json({
      exams: exams.length,
      subjects: subjects.length,
      results: results.length,
      students: students.length
    });
  }
);

/* =========================================================
   STUDENT SUMMARY
========================================================= */

app.get(
  "/api/student/summary",
  ...requireRoles("student"),
  (req, res) => {
    const schoolId = req.user.schoolId;

    const exams = read("exams").filter(
      (e) =>
        e.schoolId === schoolId &&
        e.status === "published"
    );

    const results = read("results").filter(
      (r) =>
        r.studentId === req.user.id
    );

    res.json({
      availableExams: exams.length,
      completedExams: results.length,
      averageScore:
        results.length
          ? Math.round(
              results.reduce(
                (sum, r) =>
                  sum + Number(r.percentage || 0),
                0
              ) / results.length
            )
          : 0
    });
  }
);

/* =========================================================
   SUBJECTS
========================================================= */

app.get(
  "/api/subjects",
  auth,
  (req, res) => {
    let subjects = read("subjects");

    if (req.user.role !== "superadmin") {
      subjects = subjects.filter(
        (s) =>
          s.schoolId === req.user.schoolId
      );
    }

    res.json({
      subjects
    });
  }
);

app.post(
  "/api/subjects",
  ...requireRoles(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const name = clean(req.body.name, 100);
    const code = clean(req.body.code, 30);

    const schoolId =
      req.user.role === "superadmin"
        ? clean(req.body.schoolId)
        : req.user.schoolId;

    if (!name || !schoolId) {
      return res.status(400).json({
        error: "Subject name and school are required."
      });
    }

    const subjects = read("subjects");

    const subject = {
      id: uid("sub_"),
      name,
      code,
      schoolId,
      createdAt: now()
    };

    subjects.push(subject);

    write("subjects", subjects);

    res.json({
      success: true,
      subject
    });
  }
);

app.put(
  "/api/subjects/:id",
  ...requireRoles(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const subjects = read("subjects");

    const subject = subjects.find(
      (s) => s.id === req.params.id
    );

    if (!subject) {
      return res.status(404).json({
        error: "Subject not found."
      });
    }

    if (
      req.user.role !== "superadmin" &&
      subject.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    if (req.body.name !== undefined) {
      subject.name = clean(
        req.body.name,
        100
      );
    }

    if (req.body.code !== undefined) {
      subject.code = clean(
        req.body.code,
        30
      );
    }

    write("subjects", subjects);

    res.json({
      success: true,
      subject
    });
  }
);

app.delete(
  "/api/subjects/:id",
  ...requireRoles(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const subjects = read("subjects");

    const subject = subjects.find(
      (s) => s.id === req.params.id
    );

    if (!subject) {
      return res.status(404).json({
        error: "Subject not found."
      });
    }

    if (
      req.user.role !== "superadmin" &&
      subject.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    const filtered = subjects.filter(
      (s) => s.id !== req.params.id
    );

    write("subjects", filtered);

    res.json({
      success: true
    });
  }
);

/* =========================================================
   ANNOUNCEMENTS
========================================================= */

app.get(
  "/api/announcements",
  auth,
  (req, res) => {
    let announcements =
      read("announcements");

    if (req.user.role !== "superadmin") {
      announcements =
        announcements.filter(
          (a) =>
            a.schoolId === req.user.schoolId
        );
    }

    announcements.sort(
      (a, b) =>
        new Date(b.createdAt) -
        new Date(a.createdAt)
    );

    res.json({
      announcements
    });
  }
);

app.post(
  "/api/announcements",
  ...requireRoles(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const title = clean(
      req.body.title,
      150
    );

    const message = clean(
      req.body.message,
      3000
    );

    const schoolId =
      req.user.role === "superadmin"
        ? clean(req.body.schoolId)
        : req.user.schoolId;

    if (!title || !message || !schoolId) {
      return res.status(400).json({
        error:
          "Title, message and school are required."
      });
    }

    const announcements =
      read("announcements");

    const announcement = {
      id: uid("ann_"),
      title,
      message,
      schoolId,
      createdBy: req.user.id,
      createdAt: now()
    };

    announcements.push(announcement);

    write(
      "announcements",
      announcements
    );

    res.json({
      success: true,
      announcement
    });
  }
);

app.delete(
  "/api/announcements/:id",
  ...requireRoles(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const announcements =
      read("announcements");

    const announcement =
      announcements.find(
        (a) =>
          a.id === req.params.id
      );

    if (!announcement) {
      return res.status(404).json({
        error: "Announcement not found."
      });
    }

    if (
      req.user.role !== "superadmin" &&
      announcement.schoolId !==
        req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    write(
      "announcements",
      announcements.filter(
        (a) =>
          a.id !== req.params.id
      )
    );

    res.json({
      success: true
    });
  }
);

/* =========================================================
   EXAMS
========================================================= */

app.get(
  "/api/exams",
  auth,
  (req, res) => {
    let exams = read("exams");

    if (req.user.role !== "superadmin") {
      exams = exams.filter(
        (e) =>
          e.schoolId === req.user.schoolId
      );
    }

    const questions = read("questions");
    const results = read("results");
    const subjects = read("subjects");

    exams = exams.map((exam) => {
      const subject =
        subjects.find(
          (s) => s.id === exam.subjectId
        );

      return {
        ...exam,
        subjectName:
          subject?.name || "Unknown subject",

        questionCount:
          questions.filter(
            (q) =>
              q.examId === exam.id
          ).length,

        submissionCount:
          results.filter(
            (r) =>
              r.examId === exam.id
          ).length
      };
    });

    exams.sort(
      (a, b) =>
        new Date(b.createdAt) -
        new Date(a.createdAt)
    );

    res.json({
      exams
    });
  }
);

app.get(
  "/api/exams/:id",
  auth,
  (req, res) => {
    const exam = getExam(req.params.id);

    if (!exam) {
      return res.status(404).json({
        error: "Exam not found."
      });
    }

    if (
      req.user.role !== "superadmin" &&
      exam.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    const subject = getSubject(
      exam.subjectId
    );

    const questions =
      read("questions").filter(
        (q) =>
          q.examId === exam.id
      );

    res.json({
      exam: {
        ...exam,
        subjectName:
          subject?.name || "Unknown",
        questionCount:
          questions.length
      }
    });
  }
);

app.post(
  "/api/exams",
  ...requireRoles(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const title = clean(
      req.body.title,
      150
    );

    const instructions = clean(
      req.body.instructions,
      3000
    );

    const duration =
      Number(req.body.duration) || 30;

    const status =
      ["draft", "published", "closed"].includes(
        req.body.status
      )
        ? req.body.status
        : "draft";

    const schoolId =
      req.user.role === "superadmin"
        ? clean(req.body.schoolId)
        : req.user.schoolId;

    const subjectId = clean(
      req.body.subjectId
    );

    if (!title || !schoolId || !subjectId) {
      return res.status(400).json({
        error:
          "Title, school and subject are required."
      });
    }

    const subject = getSubject(subjectId);

    if (
      !subject ||
      subject.schoolId !== schoolId
    ) {
      return res.status(400).json({
        error: "Invalid subject."
      });
    }

    const exams = read("exams");

    const exam = {
      id: uid("exam_"),
      title,
      instructions,
      duration,
      status,
      subjectId,
      schoolId,
      createdBy: req.user.id,
      createdAt: now(),
      updatedAt: now()
    };

    exams.push(exam);

    write("exams", exams);

    res.json({
      success: true,
      exam
    });
  }
);

/* =========================================================
   UPDATE EXAM
========================================================= */

app.put(
  "/api/exams/:id",
  ...requireRoles(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const exams = read("exams");

    const exam = exams.find(
      (e) => e.id === req.params.id
    );

    if (!exam) {
      return res.status(404).json({
        error: "Exam not found."
      });
    }

    if (
      req.user.role !== "superadmin" &&
      exam.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    if (req.body.title !== undefined) {
      exam.title = clean(
        req.body.title,
        150
      );
    }

    if (req.body.instructions !== undefined) {
      exam.instructions = clean(
        req.body.instructions,
        3000
      );
    }

    if (req.body.duration !== undefined) {
      exam.duration =
        Number(req.body.duration) || 30;
    }

    if (
      req.body.status &&
      ["draft", "published", "closed"].includes(
        req.body.status
      )
    ) {
      exam.status = req.body.status;
    }

    if (req.body.subjectId) {
      const subject = getSubject(
        req.body.subjectId
      );

      if (
        !subject ||
        subject.schoolId !== exam.schoolId
      ) {
        return res.status(400).json({
          error: "Invalid subject."
        });
      }

      exam.subjectId =
        req.body.subjectId;
    }

    exam.updatedAt = now();

    write("exams", exams);

    res.json({
      success: true,
      exam
    });
  }
);

/* =========================================================
   DELETE EXAM
========================================================= */

app.delete(
  "/api/exams/:id",
  ...requireRoles(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const exams = read("exams");

    const exam = exams.find(
      (e) => e.id === req.params.id
    );

    if (!exam) {
      return res.status(404).json({
        error: "Exam not found."
      });
    }

    if (
      req.user.role !== "superadmin" &&
      exam.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    write(
      "exams",
      exams.filter(
        (e) => e.id !== exam.id
      )
    );

    write(
      "questions",
      read("questions").filter(
        (q) => q.examId !== exam.id
      )
    );

    write(
      "results",
      read("results").filter(
        (r) => r.examId !== exam.id
      )
    );

    write(
      "attempts",
      read("attempts").filter(
        (a) => a.examId !== exam.id
      )
    );

    write(
      "cheatEvents",
      read("cheatEvents").filter(
        (e) => e.examId !== exam.id
      )
    );

    res.json({
      success: true
    });
  }
);

/* =========================================================
   QUESTIONS
========================================================= */

app.get(
  "/api/exams/:id/questions",
  auth,
  (req, res) => {
    const exam = getExam(req.params.id);

    if (!exam) {
      return res.status(404).json({
        error: "Exam not found."
      });
    }

    if (
      req.user.role !== "superadmin" &&
      exam.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    const questions =
      read("questions").filter(
        (q) =>
          q.examId === exam.id
      );

    res.json({
      questions
    });
  }
);

/* =========================================================
   ADD QUESTION
========================================================= */

app.post(
  "/api/exams/:id/questions",
  ...requireRoles(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const exam = getExam(req.params.id);

    if (!exam) {
      return res.status(404).json({
        error: "Exam not found."
      });
    }

    if (
      req.user.role !== "superadmin" &&
      exam.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    const question = clean(
      req.body.question,
      5000
    );

    const options = Array.isArray(
      req.body.options
    )
      ? req.body.options.map((x) =>
          clean(x, 1000)
        )
      : [];

    const answer = Number(
      req.body.answer
    );

    const points =
      Number(req.body.points) || 1;

    if (
      !question ||
      options.length < 2 ||
      !Number.isInteger(answer) ||
      answer < 0 ||
      answer >= options.length
    ) {
      return res.status(400).json({
        error:
          "Question, options and valid answer are required."
      });
    }

    const questions = read("questions");

    const item = {
      id: uid("q_"),
      examId: exam.id,
      schoolId: exam.schoolId,
      question,
      options,
      answer,
      points,
      difficulty:
        clean(req.body.difficulty, 30) ||
        "medium",
      tags: clean(
        req.body.tags,
        300
      ),
      createdAt: now()
    };

    questions.push(item);

    write("questions", questions);

    res.json({
      success: true,
      question: item
    });
  }
);

/* =========================================================
   UPDATE QUESTION
========================================================= */

app.put(
  "/api/questions/:id",
  ...requireRoles(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const questions = read("questions");

    const question = questions.find(
      (q) => q.id === req.params.id
    );

    if (!question) {
      return res.status(404).json({
        error: "Question not found."
      });
    }

    if (
      req.user.role !== "superadmin" &&
      question.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    if (req.body.question !== undefined) {
      question.question = clean(
        req.body.question,
        5000
      );
    }

    if (Array.isArray(req.body.options)) {
      question.options =
        req.body.options.map((x) =>
          clean(x, 1000)
        );
    }

    if (req.body.answer !== undefined) {
      const answer = Number(
        req.body.answer
      );

      if (
        !Number.isInteger(answer) ||
        answer < 0 ||
        answer >= question.options.length
      ) {
        return res.status(400).json({
          error: "Invalid answer."
        });
      }

      question.answer = answer;
    }

    if (req.body.points !== undefined) {
      question.points =
        Number(req.body.points) || 1;
    }

    if (req.body.difficulty !== undefined) {
      question.difficulty = clean(
        req.body.difficulty,
        30
      );
    }

    if (req.body.tags !== undefined) {
      question.tags = clean(
        req.body.tags,
        300
      );
    }

    write("questions", questions);

    res.json({
      success: true,
      question
    });
  }
);

/* =========================================================
   DELETE QUESTION
========================================================= */

app.delete(
  "/api/questions/:id",
  ...requireRoles(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const questions = read("questions");

    const question = questions.find(
      (q) => q.id === req.params.id
    );

    if (!question) {
      return res.status(404).json({
        error: "Question not found."
      });
    }

    if (
      req.user.role !== "superadmin" &&
      question.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    write(
      "questions",
      questions.filter(
        (q) => q.id !== question.id
      )
    );

    res.json({
      success: true
    });
  }
);

/* =========================================================
   QUESTION BANK
========================================================= */

app.get(
  "/api/question-bank",
  auth,
  (req, res) => {
    let questions =
      read("questions");

    if (req.user.role !== "superadmin") {
      questions = questions.filter(
        (q) =>
          q.schoolId === req.user.schoolId
      );
    }

    const search = clean(
      req.query.search,
      100
    ).toLowerCase();

    const subjectId = clean(
      req.query.subjectId
    );

    const difficulty = clean(
      req.query.difficulty
    ).toLowerCase();

    if (search) {
      questions = questions.filter(
        (q) =>
          q.question
            .toLowerCase()
            .includes(search) ||
          String(q.tags || "")
            .toLowerCase()
            .includes(search)
      );
    }

    if (difficulty) {
      questions = questions.filter(
        (q) =>
          String(q.difficulty || "")
            .toLowerCase() ===
          difficulty
      );
    }

    if (subjectId) {
      const exams = read("exams").filter(
        (e) =>
          e.subjectId === subjectId
      );

      const examIds = new Set(
        exams.map((e) => e.id)
      );

      questions = questions.filter(
        (q) => examIds.has(q.examId)
      );
    }

    res.json({
      questions
    });
  }
);

/* =========================================================
   BULK QUESTIONS
========================================================= */

app.post(
  "/api/question-bank/bulk",
  ...requireRoles(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const examId = clean(
      req.body.examId
    );

    const items = Array.isArray(
      req.body.questions
    )
      ? req.body.questions
      : [];

    const exam = getExam(examId);

    if (!exam) {
      return res.status(404).json({
        error: "Exam not found."
      });
    }

    if (
      req.user.role !== "superadmin" &&
      exam.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    if (!items.length) {
      return res.status(400).json({
        error: "No questions supplied."
      });
    }

    const questions = read("questions");

    let added = 0;

    for (const item of items) {
      const question = clean(
        item.question,
        5000
      );

      const options = Array.isArray(
        item.options
      )
        ? item.options.map((x) =>
            clean(x, 1000)
          )
        : [];

      const answer = Number(
        item.answer
      );

      if (
        !question ||
        options.length < 2 ||
        !Number.isInteger(answer) ||
        answer < 0 ||
        answer >= options.length
      ) {
        continue;
      }

      questions.push({
        id: uid("q_"),
        examId: exam.id,
        schoolId: exam.schoolId,
        question,
        options,
        answer,
        points:
          Number(item.points) || 1,
        difficulty:
          clean(item.difficulty, 30) ||
          "medium",
        tags: clean(
          item.tags,
          300
        ),
        createdAt: now()
      });

      added++;
    }

    write("questions", questions);

    res.json({
      success: true,
      added
    });
  }
);

/* =========================================================
   STUDENT: START EXAM
========================================================= */

app.post(
  "/api/exams/:id/start",
  ...requireRoles("student"),
  (req, res) => {
    const exam = getExam(req.params.id);

    if (!exam) {
      return res.status(404).json({
        error: "Exam not found."
      });
    }

    if (
      exam.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    if (exam.status !== "published") {
      return res.status(400).json({
        error: "This exam is not available."
      });
    }

    const questions =
      read("questions").filter(
        (q) =>
          q.examId === exam.id
      );

    if (!questions.length) {
      return res.status(400).json({
        error: "This exam has no questions."
      });
    }

    const attempts = read("attempts");

    const existing = attempts.find(
      (a) =>
        a.examId === exam.id &&
        a.studentId === req.user.id
    );

    if (existing) {
      if (existing.status === "active") {
        if (
          new Date(existing.endsAt).getTime() >
          Date.now()
        ) {
          return res.json({
            success: true,
            attempt: {
              ...existing,
              questions: questions.map(
                (q) => ({
                  id: q.id,
                  question: q.question,
                  options: q.options,
                  points: q.points
                })
              )
            }
          });
        }

        existing.status = "expired";
      } else {
        return res.status(409).json({
          error:
            "You have already completed this exam."
        });
      }
    }

    const startedAt = new Date();
    const endsAt = new Date(
      startedAt.getTime() +
        Number(exam.duration || 30) *
          60 *
          1000
    );

    const attempt = {
      id: uid("attempt_"),
      examId: exam.id,
      studentId: req.user.id,
      schoolId: req.user.schoolId,
      startedAt: startedAt.toISOString(),
      endsAt: endsAt.toISOString(),
      status: "active",
      answers: {},
      eventCount: 0,
      createdAt: now()
    };

    if (existing) {
      const index = attempts.findIndex(
        (a) => a.id === existing.id
      );

      attempts[index] = attempt;
    } else {
      attempts.push(attempt);
    }

    write("attempts", attempts);

    res.json({
      success: true,

      attempt: {
        ...attempt,

        questions: questions.map(
          (q) => ({
            id: q.id,
            question: q.question,
            options: q.options,
            points: q.points
          })
        )
      }
    });
  }
);

/* =========================================================
   COMPATIBILITY TAKE ROUTE
========================================================= */

app.get(
  "/api/exams/:id/take",
  ...requireRoles("student"),
  (req, res) => {
    const exam = getExam(req.params.id);

    if (!exam) {
      return res.status(404).json({
        error: "Exam not found."
      });
    }

    if (
      exam.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    if (exam.status !== "published") {
      return res.status(400).json({
        error: "Exam is not published."
      });
    }

    const questions =
      read("questions").filter(
        (q) =>
          q.examId === exam.id
      );

    res.json({
      exam: {
        id: exam.id,
        title: exam.title,
        duration: exam.duration,
        instructions: exam.instructions
      },

      questions: questions.map(
        (q) => ({
          id: q.id,
          question: q.question,
          options: q.options,
          points: q.points
        })
      )
    });
  }
);

/* =========================================================
   SAVE ATTEMPT PROGRESS
========================================================= */

app.post(
  "/api/attempts/:id/save",
  ...requireRoles("student"),
  (req, res) => {
    const attempts = read("attempts");

    const attempt = attempts.find(
      (a) => a.id === req.params.id
    );

    if (!attempt) {
      return res.status(404).json({
        error: "Attempt not found."
      });
    }

    if (
      attempt.studentId !== req.user.id
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    if (attempt.status !== "active") {
      return res.status(400).json({
        error: "This attempt is no longer active."
      });
    }

    if (
      Date.now() >=
      new Date(attempt.endsAt).getTime()
    ) {
      attempt.status = "expired";

      write("attempts", attempts);

      return res.status(400).json({
        error: "Exam time has expired."
      });
    }

    if (
      req.body.answers &&
      typeof req.body.answers === "object"
    ) {
      attempt.answers = req.body.answers;
    }

    attempt.updatedAt = now();

    write("attempts", attempts);

    res.json({
      success: true
    });
  }
);

/* =========================================================
   CBT REVIEW EVENTS
========================================================= */

const ALLOWED_EVENTS = [
  "tab_hidden",
  "tab_visible",
  "fullscreen_exit",
  "fullscreen_enter",
  "copy",
  "paste",
  "cut",
  "context_menu",
  "blur",
  "focus",
  "network_offline",
  "network_online"
];

app.post(
  "/api/attempts/:id/event",
  ...requireRoles("student"),
  (req, res) => {
    const attempts = read("attempts");

    const attempt = attempts.find(
      (a) => a.id === req.params.id
    );

    if (!attempt) {
      return res.status(404).json({
        error: "Attempt not found."
      });
    }

    if (
      attempt.studentId !== req.user.id
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    const type = clean(
      req.body.type,
      50
    );

    if (!ALLOWED_EVENTS.includes(type)) {
      return res.status(400).json({
        error: "Invalid event type."
      });
    }

    if (attempt.eventCount >= 500) {
      return res.json({
        success: true
      });
    }

    const events = read("cheatEvents");

    events.push({
      id: uid("event_"),
      attemptId: attempt.id,
      examId: attempt.examId,
      studentId: req.user.id,
      schoolId: req.user.schoolId,
      type,
      createdAt: now()
    });

    attempt.eventCount =
      Number(attempt.eventCount || 0) + 1;

    write("cheatEvents", events);
    write("attempts", attempts);

    res.json({
      success: true
    });
  }
);

/* =========================================================
   SUBMIT EXAM
========================================================= */

app.post(
  "/api/attempts/:id/submit",
  ...requireRoles("student"),
  (req, res) => {
    const attempts = read("attempts");

    const attempt = attempts.find(
      (a) => a.id === req.params.id
    );

    if (!attempt) {
      return res.status(404).json({
        error: "Attempt not found."
      });
    }

    if (
      attempt.studentId !== req.user.id
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    if (attempt.status !== "active") {
      return res.status(409).json({
        error:
          "This attempt has already been submitted."
      });
    }

    const exams = read("exams");

    const exam = exams.find(
      (e) => e.id === attempt.examId
    );

    if (!exam) {
      return res.status(404).json({
        error: "Exam not found."
      });
    }

    const questions =
      read("questions").filter(
        (q) =>
          q.examId === exam.id
      );

    const answers =
      req.body.answers &&
      typeof req.body.answers === "object"
        ? req.body.answers
        : attempt.answers || {};

    let score = 0;
    let total = 0;
    let answered = 0;

    for (const question of questions) {
      const points =
        Number(question.points) || 1;

      total += points;

      const submitted =
        answers[question.id];

      if (
        submitted !== undefined &&
        submitted !== null &&
        submitted !== ""
      ) {
        answered++;
      }

      if (
        Number(submitted) ===
        Number(question.answer)
      ) {
        score += points;
      }
    }

    const percentage =
      total > 0
        ? Math.round(
            (score / total) * 100
          )
        : 0;

    const expired =
      Date.now() >
      new Date(attempt.endsAt).getTime();

    const results = read("results");

    const result = {
      id: uid("result_"),
      examId: exam.id,
      studentId: req.user.id,
      schoolId: req.user.schoolId,
      score,
      total,
      percentage,
      answered,
      questionCount: questions.length,
      expired,
      answers,
      submittedAt: now(),
      createdAt: now()
    };

    results.push(result);

    attempt.answers = answers;
    attempt.status = "submitted";
    attempt.submittedAt =
      result.submittedAt;

    write("results", results);
    write("attempts", attempts);

    res.json({
      success: true,
      result
    });
  }
);

/* =========================================================
   OLD SUBMIT COMPATIBILITY
========================================================= */

app.post(
  "/api/exams/:id/submit",
  ...requireRoles("student"),
  (req, res) => {
    const exam = getExam(req.params.id);

    if (!exam) {
      return res.status(404).json({
        error: "Exam not found."
      });
    }

    if (
      exam.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    const questions =
      read("questions").filter(
        (q) =>
          q.examId === exam.id
      );

    const answers =
      req.body.answers &&
      typeof req.body.answers === "object"
        ? req.body.answers
        : {};

    let score = 0;
    let total = 0;

    for (const q of questions) {
      const points =
        Number(q.points) || 1;

      total += points;

      if (
        Number(answers[q.id]) ===
        Number(q.answer)
      ) {
        score += points;
      }
    }

    const percentage =
      total
        ? Math.round(
            (score / total) * 100
          )
        : 0;

    const results = read("results");

    const result = {
      id: uid("result_"),
      examId: exam.id,
      studentId: req.user.id,
      schoolId: req.user.schoolId,
      score,
      total,
      percentage,
      questionCount: questions.length,
      answers,
      submittedAt: now(),
      createdAt: now()
    };

    results.push(result);

    write("results", results);

    res.json({
      success: true,
      result
    });
  }
);

/* =========================================================
   RESULTS
========================================================= */

app.get(
  "/api/results",
  auth,
  (req, res) => {
    let results = read("results");

    if (req.user.role === "student") {
      results = results.filter(
        (r) =>
          r.studentId === req.user.id
      );
    } else if (
      req.user.role !== "superadmin"
    ) {
      results = results.filter(
        (r) =>
          r.schoolId === req.user.schoolId
      );
    }

    const users = read("users");
    const exams = read("exams");

    results = results.map((result) => {
      const student = users.find(
        (u) =>
          u.id === result.studentId
      );

      const exam = exams.find(
        (e) =>
          e.id === result.examId
      );

      return {
        ...result,
        studentName:
          student?.fullName || "Unknown",
        studentUsername:
          student?.username || "",
        examTitle:
          exam?.title || "Unknown exam"
      };
    });

    results.sort(
      (a, b) =>
        new Date(b.submittedAt) -
        new Date(a.submittedAt)
    );

    res.json({
      results
    });
  }
);

/* =========================================================
   RESULT DETAILS
========================================================= */

app.get(
  "/api/results/:id",
  auth,
  (req, res) => {
    const result = read("results").find(
      (r) =>
        r.id === req.params.id
    );

    if (!result) {
      return res.status(404).json({
        error: "Result not found."
      });
    }

    if (
      req.user.role === "student" &&
      result.studentId !== req.user.id
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    if (
      req.user.role !== "superadmin" &&
      result.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    const exam = getExam(
      result.examId
    );

    res.json({
      result,
      exam: exam || null
    });
  }
);

/* =========================================================
   CHEAT/REVIEW EVENTS FOR ADMIN/TEACHER
========================================================= */

app.get(
  "/api/exams/:id/cheat-events",
  ...requireRoles(
    "school_admin",
    "teacher",
    "superadmin"
  ),
  (req, res) => {
    const exam = getExam(req.params.id);

    if (!exam) {
      return res.status(404).json({
        error: "Exam not found."
      });
    }

    if (
      req.user.role !== "superadmin" &&
      exam.schoolId !== req.user.schoolId
    ) {
      return res.status(403).json({
        error: "Access denied."
      });
    }

    const events =
      read("cheatEvents").filter(
        (e) =>
          e.examId === exam.id
      );

    const users = read("users");

    const enriched = events.map(
      (event) => {
        const student = users.find(
          (u) =>
            u.id === event.studentId
        );

        return {
          ...event,
          studentName:
            student?.fullName ||
            "Unknown",
          username:
            student?.username || ""
        };
      }
    );

    res.json({
      events: enriched
    });
  }
);

/* =========================================================
   SUPERADMIN SCHOOLS
========================================================= */

app.get(
  "/api/superadmin/schools",
  ...requireRoles("superadmin"),
  (req, res) => {
    const schools = read("schools");

    const users = read("users");

    const enriched = schools.map(
      (school) => ({
        ...school,

        userCount:
          users.filter(
            (u) =>
              u.schoolId === school.id
          ).length,

        studentCount:
          users.filter(
            (u) =>
              u.schoolId === school.id &&
              u.role === "student"
          ).length,

        teacherCount:
          users.filter(
            (u) =>
              u.schoolId === school.id &&
              u.role === "teacher"
          ).length
      })
    );

    res.json({
      schools: enriched
    });
  }
);

/* =========================================================
   SUPERADMIN CREATE SCHOOL
========================================================= */

app.post(
  "/api/superadmin/schools",
  ...requireRoles("superadmin"),
  (req, res) => {
    const name = clean(
      req.body.name,
      120
    );

    if (!name) {
      return res.status(400).json({
        error: "School name is required."
      });
    }

    const schools = read("schools");

    const school = {
      id: uid("school_"),
      name,
      motto: clean(
        req.body.motto,
        200
      ),
      logo: "",
      primaryColor:
        clean(
          req.body.primaryColor,
          30
        ) || "#2563eb",
      secondaryColor:
        clean(
          req.body.secondaryColor,
          30
        ) || "#16a34a",
      theme: "light",
      active: true,
      createdAt: now()
    };

    schools.push(school);

    write("schools", schools);

    res.json({
      success: true,
      school
    });
  }
);

/* =========================================================
   SUPERADMIN UPDATE SCHOOL
========================================================= */

app.put(
  "/api/superadmin/schools/:id",
  ...requireRoles("superadmin"),
  (req, res) => {
    const schools = read("schools");

    const school = schools.find(
      (s) =>
        s.id === req.params.id
    );

    if (!school) {
      return res.status(404).json({
        error: "School not found."
      });
    }

    if (req.body.name !== undefined) {
      school.name = clean(
        req.body.name,
        120
      );
    }

    if (req.body.motto !== undefined) {
      school.motto = clean(
        req.body.motto,
        200
      );
    }

    if (req.body.primaryColor !== undefined) {
      school.primaryColor =
        clean(
          req.body.primaryColor,
          30
        );
    }

    if (req.body.secondaryColor !== undefined) {
      school.secondaryColor =
        clean(
          req.body.secondaryColor,
          30
        );
    }

    if (req.body.theme !== undefined) {
      school.theme =
        ["light", "dark", "system"].includes(
          req.body.theme
        )
          ? req.body.theme
          : school.theme;
    }

    if (req.body.active !== undefined) {
      school.active =
        Boolean(req.body.active);
    }

    write("schools", schools);

    res.json({
      success: true,
      school
    });
  }
);

/* =========================================================
   SUPERADMIN ALL USERS
========================================================= */

app.get(
  "/api/superadmin/all-users",
  ...requireRoles("superadmin"),
  (req, res) => {
    const users = read("users");
    const schools = read("schools");

    const result = users.map((user) => {
      const school = schools.find(
        (s) =>
          s.id === user.schoolId
      );

      return {
        ...safeUser(user),
        schoolName:
          school?.name || "Platform"
      };
    });

    res.json({
      users: result
    });
  }
);

/* =========================================================
   404 API
========================================================= */

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API route not found",
    path: req.path
  });
});

/* =========================================================
   FRONTEND FALLBACK
========================================================= */

app.use((req, res, next) => {
  if (
    req.method !== "GET" ||
    req.path.startsWith("/uploads/")
  ) {
    return next();
  }

  const indexFile =
    path.join(
      ROOT,
      "public",
      "index.html"
    );

  if (fs.existsSync(indexFile)) {
    return res.sendFile(indexFile);
  }

  res.status(404).send(
    "SchoolHub Pro frontend is not installed."
  );
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

    if (
      error instanceof multer.MulterError
    ) {
      return res.status(400).json({
        error:
          error.message ||
          "File upload error."
      });
    }

    res.status(500).json({
      error:
        error.message ||
        "Internal server error."
    });
  }
);

/* =========================================================
   START SERVER
========================================================= */

const server = app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log("");
    console.log(
      "========================================"
    );
    console.log(
      "       SCHOOLHUB PRO SERVER"
    );
    console.log(
      "========================================"
    );
    console.log(
      `Port: ${PORT}`
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
      "========================================"
    );
    console.log("");
  }
);

/* =========================================================
   PROCESS ERROR HANDLING
========================================================= */

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

/*
 Do not immediately terminate the process on uncaught errors.
 Railway can then provide useful logs while the server
 remains available where possible.
*/

module.exports = app;
