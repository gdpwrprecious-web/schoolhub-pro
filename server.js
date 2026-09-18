// ============================================================
// SCHOOLHUB PRO
// MAIN SERVER - RAILWAY READY
// Multi-School School Management + CBT Platform
// ============================================================

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
require("dotenv").config();

// ------------------------------------------------------------
// APP
// ------------------------------------------------------------

const app = express();

app.set("trust proxy", 1);

const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;

// Railway persistent volume:
// STORAGE_ROOT=/app/storage
const STORAGE_ROOT = process.env.STORAGE_ROOT || path.join(ROOT, "storage");

const DATA_DIR = path.join(STORAGE_ROOT, "data");
const UPLOAD_DIR = path.join(STORAGE_ROOT, "uploads");
const PROFILE_DIR = path.join(UPLOAD_DIR, "profiles");
const SCHOOL_UPLOAD_DIR = path.join(UPLOAD_DIR, "schools");

for (const dir of [
    STORAGE_ROOT,
    DATA_DIR,
    UPLOAD_DIR,
    PROFILE_DIR,
    SCHOOL_UPLOAD_DIR
]) {
    fs.mkdirSync(dir, { recursive: true });
}

// ------------------------------------------------------------
// JSON DATABASE FILES
// ------------------------------------------------------------

const FILES = {
    users: path.join(DATA_DIR, "users.json"),
    schools: path.join(DATA_DIR, "schools.json"),
    subjects: path.join(DATA_DIR, "subjects.json"),
    announcements: path.join(DATA_DIR, "announcements.json"),
    exams: path.join(DATA_DIR, "exams.json"),
    questions: path.join(DATA_DIR, "questions.json"),
    results: path.join(DATA_DIR, "results.json")
};

function ensureFile(file) {
    if (!fs.existsSync(file)) {
        fs.writeFileSync(file, "[]", "utf8");
    }
}

Object.values(FILES).forEach(ensureFile);

function read(name) {
    const file = FILES[name];

    try {
        ensureFile(file);
        const raw = fs.readFileSync(file, "utf8");

        if (!raw.trim()) return [];

        const parsed = JSON.parse(raw);

        return Array.isArray(parsed) ? parsed : [];
    } catch (error) {
        console.error(`DATABASE READ ERROR [${name}]`, error);
        return [];
    }
}

function write(name, data) {
    const file = FILES[name];
    const temp = `${file}.tmp`;

    try {
        fs.writeFileSync(
            temp,
            JSON.stringify(data, null, 2),
            "utf8"
        );

        fs.renameSync(temp, file);
    } catch (error) {
        console.error(`DATABASE WRITE ERROR [${name}]`, error);

        try {
            if (fs.existsSync(temp)) {
                fs.unlinkSync(temp);
            }
        } catch (_) {}

        throw error;
    }
}

// ------------------------------------------------------------
// HELPERS
// ------------------------------------------------------------

function uid(prefix = "") {
    return (
        prefix +
        crypto.randomBytes(10).toString("hex")
    );
}

function now() {
    return new Date().toISOString();
}

function clean(value, max = 500) {
    if (value === undefined || value === null) return "";
    return String(value).trim().slice(0, max);
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

function schoolOf(id) {
    return read("schools").find(s => s.id === id);
}

function userOf(id) {
    return read("users").find(u => u.id === id);
}

function subjectOf(id) {
    return read("subjects").find(s => s.id === id);
}

function examOf(id) {
    return read("exams").find(e => e.id === id);
}

function questionsOf(examId) {
    return read("questions").filter(q => q.examId === examId);
}

function userCanAccessSchool(user, schoolId) {
    return (
        user &&
        (
            user.role === "superadmin" ||
            user.schoolId === schoolId
        )
    );
}

// ------------------------------------------------------------
// EXPRESS MIDDLEWARE
// ------------------------------------------------------------

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({
    extended: true,
    limit: "10mb"
}));

// ------------------------------------------------------------
// SESSION
// ------------------------------------------------------------

const SESSION_SECRET =
    process.env.SESSION_SECRET ||
    crypto.randomBytes(48).toString("hex");

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

// ------------------------------------------------------------
// PASSPORT
// ------------------------------------------------------------

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    const user = userOf(id);

    if (!user) {
        return done(null, false);
    }

    done(null, user);
});

// ------------------------------------------------------------
// UPLOADS
// ------------------------------------------------------------

const imageStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        if (req.originalUrl.includes("/school/logo")) {
            cb(null, SCHOOL_UPLOAD_DIR);
        } else {
            cb(null, PROFILE_DIR);
        }
    },

    filename: function (req, file, cb) {
        const ext =
            path.extname(file.originalname).toLowerCase();

        cb(
            null,
            `${uid()}${ext}`
        );
    }
});

const upload = multer({
    storage: imageStorage,

    limits: {
        fileSize: 5 * 1024 * 1024
    },

    fileFilter: function (req, file, cb) {
        const allowed = [
            "image/png",
            "image/jpeg",
            "image/webp"
        ];

        if (!allowed.includes(file.mimetype)) {
            return cb(
                new Error("Only PNG, JPEG and WEBP images are allowed.")
            );
        }

        cb(null, true);
    }
});

// ------------------------------------------------------------
// STATIC FILES
// ------------------------------------------------------------

app.use(
    "/uploads",
    express.static(UPLOAD_DIR)
);

app.use(
    express.static(
        path.join(ROOT, "public")
    )
);

// ------------------------------------------------------------
// AUTH MIDDLEWARE
// ------------------------------------------------------------

function auth(req, res, next) {
    const userId =
        req.session.userId ||
        (req.user && req.user.id);

    if (!userId) {
        return res.status(401).json({
            error: "Authentication required"
        });
    }

    const user = userOf(userId);

    if (!user) {
        req.session.destroy(() => {});

        return res.status(401).json({
            error: "User account not found"
        });
    }

    if (user.active === false) {
        return res.status(403).json({
            error: "This account is inactive"
        });
    }

    req.currentUser = user;

    next();
}

function role(...roles) {
    return function (req, res, next) {
        if (!req.currentUser) {
            return res.status(401).json({
                error: "Authentication required"
            });
        }

        if (!roles.includes(req.currentUser.role)) {
            return res.status(403).json({
                error: "You do not have permission for this action"
            });
        }

        next();
    };
}

// ------------------------------------------------------------
// GOOGLE AUTH
// ------------------------------------------------------------

const GOOGLE_CLIENT_ID =
    process.env.GOOGLE_CLIENT_ID || "";

const GOOGLE_CLIENT_SECRET =
    process.env.GOOGLE_CLIENT_SECRET || "";

const GOOGLE_CALLBACK_URL =
    process.env.GOOGLE_CALLBACK_URL ||
    (
        process.env.APP_URL
            ? `${process.env.APP_URL.replace(/\/$/, "")}/auth/google/callback`
            : ""
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
                clientSecret: GOOGLE_CLIENT_SECRET,
                callbackURL: GOOGLE_CALLBACK_URL
            },

            function (
                accessToken,
                refreshToken,
                profile,
                done
            ) {
                try {
                    let users = read("users");

                    const email =
                        profile.emails &&
                        profile.emails[0]
                            ? profile.emails[0].value.toLowerCase()
                            : "";

                    let user =
                        users.find(
                            u =>
                                u.googleId === profile.id
                        ) ||
                        (
                            email
                                ? users.find(
                                    u =>
                                        u.email &&
                                        u.email.toLowerCase() === email
                                )
                                : null
                        );

                    if (!user) {
                        return done(
                            null,
                            false,
                            {
                                message:
                                    "No SchoolHub account exists for this Google email. Please register first."
                            }
                        );
                    }

                    user.googleId = profile.id;
                    user.provider = "google";

                    if (
                        profile.photos &&
                        profile.photos[0]
                    ) {
                        user.profilePicture =
                            profile.photos[0].value;
                    }

                    user.updatedAt = now();

                    users = users.map(u =>
                        u.id === user.id
                            ? user
                            : u
                    );

                    write("users", users);

                    return done(null, user);

                } catch (error) {
                    console.error(
                        "GOOGLE STRATEGY ERROR",
                        error
                    );

                    return done(error);
                }
            }
        )
    );
}

// ------------------------------------------------------------
// HEALTH
// ------------------------------------------------------------

app.get("/api/health", (req, res) => {
    res.json({
        ok: true,
        status: "online",
        service: "SchoolHub Pro",
        version: "4.0.0",
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

// ------------------------------------------------------------
// PLATFORM
// ------------------------------------------------------------

app.get("/api/platform-config", (req, res) => {
    res.json({
        platformName:
            process.env.PLATFORM_NAME ||
            "SchoolHub Pro",

        description:
            "Smart school management for modern schools.",

        googleAuth: googleConfigured
    });
});

// ------------------------------------------------------------
// CURRENT USER
// ------------------------------------------------------------

app.get("/api/me", auth, (req, res) => {
    res.json({
        user: safeUser(req.currentUser),
        school:
            req.currentUser.schoolId
                ? schoolOf(req.currentUser.schoolId) || null
                : null
    });
});

// ------------------------------------------------------------
// REGISTER
// ------------------------------------------------------------

app.post("/api/register", async (req, res) => {
    try {
        const schoolName = clean(
            req.body.schoolName ||
            req.body.name,
            150
        );

        const motto = clean(
            req.body.motto,
            250
        );

        const fullName = clean(
            req.body.fullName ||
            req.body.name,
            120
        );

        const username = clean(
            req.body.username,
            80
        ).toLowerCase();

        const email = clean(
            req.body.email,
            150
        ).toLowerCase();

        const password =
            req.body.password || "";

        if (
            !schoolName ||
            !fullName ||
            !username ||
            !email ||
            !password
        ) {
            return res.status(400).json({
                error:
                    "School name, full name, username, email and password are required."
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                error:
                    "Password must contain at least 6 characters."
            });
        }

        let users = read("users");
        let schools = read("schools");

        if (
            users.some(
                u =>
                    u.username &&
                    u.username.toLowerCase() === username
            )
        ) {
            return res.status(409).json({
                error: "Username already exists."
            });
        }

        if (
            users.some(
                u =>
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

        const passwordHash =
            await bcrypt.hash(password, 12);

        const user = {
            id: uid("user_"),
            fullName,
            username,
            email,
            passwordHash,
            role: "school_admin",
            schoolId,
            active: true,
            provider: "local",
            profilePicture: "",
            createdAt: now()
        };

        schools.push(school);
        users.push(user);

        write("schools", schools);
        write("users", users);

        req.session.userId = user.id;

        res.json({
            success: true,
            user: safeUser(user),
            school,
            redirect: "/admin.html"
        });

    } catch (error) {
        console.error("REGISTER ERROR", error);

        res.status(500).json({
            error: "Registration failed."
        });
    }
});

// ------------------------------------------------------------
// LOGIN
// ------------------------------------------------------------

app.post("/api/login", async (req, res) => {
    try {
        const identifier = clean(
            req.body.identifier ||
            req.body.username ||
            req.body.email,
            150
        ).toLowerCase();

        const password =
            req.body.password || "";

        if (!identifier || !password) {
            return res.status(400).json({
                error:
                    "Username/email and password are required."
            });
        }

        const users = read("users");

        const user = users.find(
            u =>
                (
                    u.username &&
                    u.username.toLowerCase() === identifier
                ) ||
                (
                    u.email &&
                    u.email.toLowerCase() === identifier
                )
        );

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

        if (!user.passwordHash) {
            return res.status(401).json({
                error:
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
                error: "Invalid login details."
            });
        }

        req.session.userId = user.id;

        let redirect = "/login.html";

        if (
            user.role === "superadmin" ||
            user.role === "school_admin"
        ) {
            redirect = "/admin.html";
        } else if (user.role === "teacher") {
            redirect = "/teacher.html";
        } else if (user.role === "student") {
            redirect = "/student.html";
        }

        res.json({
            success: true,
            user: safeUser(user),
            redirect
        });

    } catch (error) {
        console.error("LOGIN ERROR", error);

        res.status(500).json({
            error:
                "An internal error occurred during login."
        });
    }
});

// ------------------------------------------------------------
// LOGOUT
// ------------------------------------------------------------

app.post("/api/logout", (req, res) => {
    req.session.destroy(() => {
        res.clearCookie("connect.sid");

        res.json({
            success: true
        });
    });
});

// ------------------------------------------------------------
// GOOGLE LOGIN
// ------------------------------------------------------------

app.get("/auth/google", (req, res) => {
    if (!googleConfigured) {
        return res.status(503).send(`
            <h1>Google Sign-In Not Configured</h1>
            <p>Please configure GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET and GOOGLE_CALLBACK_URL.</p>
        `);
    }

    passport.authenticate(
        "google",
        {
            scope: [
                "profile",
                "email"
            ]
        }
    )(req, res);
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
            (err, user) => {
                if (err) {
                    console.error(
                        "GOOGLE CALLBACK ERROR",
                        err
                    );

                    return res.redirect(
                        "/login.html?error=google_failed"
                    );
                }

                if (!user) {
                    return res.redirect(
                        "/login.html?error=google_account_not_found"
                    );
                }

                req.logIn(user, loginError => {
                    if (loginError) {
                        console.error(
                            "GOOGLE SESSION ERROR",
                            loginError
                        );

                        return res.redirect(
                            "/login.html?error=session_failed"
                        );
                    }

                    req.session.userId = user.id;

                    if (
                        user.role === "superadmin" ||
                        user.role === "school_admin"
                    ) {
                        return res.redirect(
                            "/admin.html"
                        );
                    }

                    if (user.role === "teacher") {
                        return res.redirect(
                            "/teacher.html"
                        );
                    }

                    if (user.role === "student") {
                        return res.redirect(
                            "/student.html"
                        );
                    }

                    return res.redirect(
                        "/login.html"
                    );
                });
            }
        )(req, res, next);
    }
);

// ------------------------------------------------------------
// SCHOOL
// ------------------------------------------------------------

app.get("/api/school", auth, (req, res) => {
    if (!req.currentUser.schoolId) {
        return res.json({
            school: null
        });
    }

    const school =
        schoolOf(req.currentUser.schoolId);

    res.json({
        school: school || null
    });
});

// ------------------------------------------------------------
// SCHOOL BRANDING
// ------------------------------------------------------------

app.put(
    "/api/school/branding",
    auth,
    role("school_admin", "superadmin"),
    (req, res) => {
        const schoolId =
            req.currentUser.role === "superadmin"
                ? clean(req.body.schoolId)
                : req.currentUser.schoolId;

        const schools = read("schools");

        const index =
            schools.findIndex(
                s => s.id === schoolId
            );

        if (index === -1) {
            return res.status(404).json({
                error: "School not found."
            });
        }

        const school = schools[index];

        if (req.body.name !== undefined) {
            school.name = clean(
                req.body.name,
                150
            );
        }

        if (req.body.motto !== undefined) {
            school.motto = clean(
                req.body.motto,
                250
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
                ["light", "dark"].includes(
                    req.body.theme
                )
                    ? req.body.theme
                    : "light";
        }

        school.updatedAt = now();

        write("schools", schools);

        res.json({
            success: true,
            school
        });
    }
);

// ------------------------------------------------------------
// SCHOOL LOGO
// ------------------------------------------------------------

app.post(
    "/api/school/logo",
    auth,
    role("school_admin", "superadmin"),
    upload.single("logo"),
    (req, res) => {
        if (!req.file) {
            return res.status(400).json({
                error: "No logo uploaded."
            });
        }

        const schoolId =
            req.currentUser.role === "superadmin"
                ? clean(req.body.schoolId)
                : req.currentUser.schoolId;

        const schools = read("schools");

        const school =
            schools.find(
                s => s.id === schoolId
            );

        if (!school) {
            return res.status(404).json({
                error: "School not found."
            });
        }

        school.logo =
            `/uploads/schools/${req.file.filename}`;

        school.updatedAt = now();

        write("schools", schools);

        res.json({
            success: true,
            school
        });
    }
);

// ------------------------------------------------------------
// PROFILE PICTURE
// ------------------------------------------------------------

app.post(
    "/api/profile-picture",
    auth,
    upload.single("profilePicture"),
    (req, res) => {
        if (!req.file) {
            return res.status(400).json({
                error:
                    "No profile picture uploaded."
            });
        }

        const users = read("users");

        const index =
            users.findIndex(
                u =>
                    u.id ===
                    req.currentUser.id
            );

        if (index === -1) {
            return res.status(404).json({
                error: "User not found."
            });
        }

        users[index].profilePicture =
            `/uploads/profiles/${req.file.filename}`;

        users[index].updatedAt = now();

        write("users", users);

        res.json({
            success: true,
            user: safeUser(users[index])
        });
    }
);

// ------------------------------------------------------------
// USERS
// ------------------------------------------------------------

app.get(
    "/api/users",
    auth,
    role("school_admin", "superadmin"),
    (req, res) => {
        let users = read("users");

        if (
            req.currentUser.role !==
            "superadmin"
        ) {
            users =
                users.filter(
                    u =>
                        u.schoolId ===
                        req.currentUser.schoolId
                );
        }

        res.json({
            users: users.map(safeUser)
        });
    }
);

app.post(
    "/api/users",
    auth,
    role("school_admin", "superadmin"),
    async (req, res) => {
        try {
            const fullName =
                clean(req.body.fullName, 120);

            const username =
                clean(
                    req.body.username,
                    80
                ).toLowerCase();

            const email =
                clean(
                    req.body.email,
                    150
                ).toLowerCase();

            const password =
                req.body.password || "";

            let userRole =
                clean(req.body.role, 50);

            if (
                ![
                    "teacher",
                    "student",
                    "school_admin"
                ].includes(userRole)
            ) {
                userRole = "student";
            }

            if (
                req.currentUser.role !==
                "superadmin" &&
                userRole === "school_admin"
            ) {
                return res.status(403).json({
                    error:
                        "Only the superadmin can create school administrators."
                });
            }

            const schoolId =
                req.currentUser.role ===
                "superadmin"
                    ? clean(req.body.schoolId)
                    : req.currentUser.schoolId;

            if (!schoolId) {
                return res.status(400).json({
                    error:
                        "School ID is required."
                });
            }

            if (
                !schoolOf(schoolId)
            ) {
                return res.status(404).json({
                    error: "School not found."
                });
            }

            if (
                !fullName ||
                !username ||
                !email ||
                !password
            ) {
                return res.status(400).json({
                    error:
                        "Full name, username, email and password are required."
                });
            }

            const users = read("users");

            if (
                users.some(
                    u =>
                        u.username &&
                        u.username.toLowerCase() ===
                        username
                )
            ) {
                return res.status(409).json({
                    error:
                        "Username already exists."
                });
            }

            if (
                users.some(
                    u =>
                        u.email &&
                        u.email.toLowerCase() ===
                        email
                )
            ) {
                return res.status(409).json({
                    error:
                        "Email already exists."
                });
            }

            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );

            const user = {
                id: uid("user_"),
                fullName,
                username,
                email,
                passwordHash,
                role: userRole,
                schoolId,
                active: true,
                provider: "local",
                profilePicture: "",
                createdAt: now()
            };

            users.push(user);

            write("users", users);

            res.json({
                success: true,
                user: safeUser(user)
            });

        } catch (error) {
            console.error(
                "CREATE USER ERROR",
                error
            );

            res.status(500).json({
                error:
                    "Could not create user."
            });
        }
    }
);

// ------------------------------------------------------------
// UPDATE USER
// ------------------------------------------------------------

app.put(
    "/api/users/:id",
    auth,
    role("school_admin", "superadmin"),
    async (req, res) => {
        try {
            const users = read("users");

            const index =
                users.findIndex(
                    u =>
                        u.id ===
                        req.params.id
                );

            if (index === -1) {
                return res.status(404).json({
                    error:
                        "User not found."
                });
            }

            const user = users[index];

            if (
                req.currentUser.role !==
                "superadmin" &&
                user.schoolId !==
                    req.currentUser.schoolId
            ) {
                return res.status(403).json({
                    error:
                        "You cannot manage users from another school."
                });
            }

            if (req.body.fullName !== undefined) {
                user.fullName =
                    clean(
                        req.body.fullName,
                        120
                    );
            }

            if (req.body.email !== undefined) {
                user.email =
                    clean(
                        req.body.email,
                        150
                    ).toLowerCase();
            }

            if (req.body.role !== undefined) {
                const allowed = [
                    "teacher",
                    "student",
                    "school_admin"
                ];

                if (
                    req.currentUser.role ===
                    "superadmin" &&
                    allowed.includes(
                        req.body.role
                    )
                ) {
                    user.role =
                        req.body.role;
                } else if (
                    req.currentUser.role !==
                        "superadmin" &&
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
                req.body.password
            ) {
                user.passwordHash =
                    await bcrypt.hash(
                        req.body.password,
                        12
                    );
            }

            user.updatedAt = now();

            write("users", users);

            res.json({
                success: true,
                user: safeUser(user)
            });

        } catch (error) {
            console.error(
                "UPDATE USER ERROR",
                error
            );

            res.status(500).json({
                error:
                    "Could not update user."
            });
        }
    }
);

// ------------------------------------------------------------
// DELETE USER
// ------------------------------------------------------------

app.delete(
    "/api/users/:id",
    auth,
    role("school_admin", "superadmin"),
    (req, res) => {
        const users = read("users");

        const user =
            users.find(
                u =>
                    u.id ===
                    req.params.id
            );

        if (!user) {
            return res.status(404).json({
                error:
                    "User not found."
            });
        }

        if (
            req.currentUser.role !==
                "superadmin" &&
            user.schoolId !==
                req.currentUser.schoolId
        ) {
            return res.status(403).json({
                error:
                    "You cannot delete this user."
            });
        }

        if (
            user.id ===
            req.currentUser.id
        ) {
            return res.status(400).json({
                error:
                    "You cannot delete your own account."
            });
        }

        write(
            "users",
            users.filter(
                u =>
                    u.id !==
                    req.params.id
            )
        );

        res.json({
            success: true
        });
    }
);

// ------------------------------------------------------------
// ADMIN SUMMARY
// ------------------------------------------------------------

app.get(
    "/api/admin/summary",
    auth,
    role("school_admin", "superadmin"),
    (req, res) => {
        const schoolId =
            req.currentUser.role ===
            "superadmin"
                ? null
                : req.currentUser.schoolId;

        let users = read("users");

        if (schoolId) {
            users =
                users.filter(
                    u =>
                        u.schoolId ===
                        schoolId
                );
        }

        let subjects = read("subjects");
        let exams = read("exams");
        let results = read("results");

        if (schoolId) {
            subjects =
                subjects.filter(
                    s =>
                        s.schoolId ===
                        schoolId
                );

            exams =
                exams.filter(
                    e =>
                        e.schoolId ===
                        schoolId
                );

            results =
                results.filter(
                    r =>
                        r.schoolId ===
                        schoolId
                );
        }

        res.json({
            students:
                users.filter(
                    u =>
                        u.role ===
                        "student"
                ).length,

            teachers:
                users.filter(
                    u =>
                        u.role ===
                        "teacher"
                ).length,

            admins:
                users.filter(
                    u =>
                        u.role ===
                        "school_admin"
                ).length,

            schools:
                schoolId
                    ? 1
                    : read("schools").length,

            subjects:
                subjects.length,

            exams:
                exams.length,

            results:
                results.length
        });
    }
);

// ------------------------------------------------------------
// TEACHER SUMMARY
// ------------------------------------------------------------

app.get(
    "/api/teacher/summary",
    auth,
    role("teacher", "school_admin", "superadmin"),
    (req, res) => {
        const schoolId =
            req.currentUser.schoolId;

        const exams =
            read("exams").filter(
                e =>
                    e.schoolId ===
                    schoolId
            );

        const subjects =
            read("subjects").filter(
                s =>
                    s.schoolId ===
                    schoolId
            );

        const results =
            read("results").filter(
                r =>
                    r.schoolId ===
                    schoolId
            );

        res.json({
            exams: exams.length,
            subjects: subjects.length,
            results: results.length,
            publishedExams:
                exams.filter(
                    e =>
                        e.status ===
                        "published"
                ).length
        });
    }
);

// ------------------------------------------------------------
// STUDENT SUMMARY
// ------------------------------------------------------------

app.get(
    "/api/student/summary",
    auth,
    role("student"),
    (req, res) => {
        const exams =
            read("exams").filter(
                e =>
                    e.schoolId ===
                    req.currentUser.schoolId &&
                    e.status ===
                    "published"
            );

        const results =
            read("results").filter(
                r =>
                    r.studentId ===
                    req.currentUser.id
            );

        res.json({
            availableExams:
                exams.length,

            completedExams:
                results.length,

            averageScore:
                results.length
                    ? Math.round(
                        results.reduce(
                            (sum, r) =>
                                sum +
                                Number(
                                    r.percentage ||
                                    0
                                ),
                            0
                        ) /
                        results.length
                    )
                    : 0
        });
    }
);

// ------------------------------------------------------------
// SUBJECTS
// ------------------------------------------------------------

app.get(
    "/api/subjects",
    auth,
    (req, res) => {
        const subjects =
            read("subjects").filter(
                s =>
                    s.schoolId ===
                    req.currentUser.schoolId
            );

        res.json({
            subjects
        });
    }
);

app.post(
    "/api/subjects",
    auth,
    role("teacher", "school_admin", "superadmin"),
    (req, res) => {
        const name =
            clean(req.body.name, 120);

        const code =
            clean(req.body.code, 30);

        if (!name) {
            return res.status(400).json({
                error:
                    "Subject name is required."
            });
        }

        const subjects =
            read("subjects");

        const subject = {
            id: uid("subject_"),
            schoolId:
                req.currentUser.schoolId,
            name,
            code,
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
    auth,
    role("teacher", "school_admin", "superadmin"),
    (req, res) => {
        const subjects =
            read("subjects");

        const index =
            subjects.findIndex(
                s =>
                    s.id ===
                    req.params.id
            );

        if (index === -1) {
            return res.status(404).json({
                error:
                    "Subject not found."
            });
        }

        if (
            subjects[index].schoolId !==
            req.currentUser.schoolId
        ) {
            return res.status(403).json({
                error:
                    "Access denied."
            });
        }

        if (req.body.name !== undefined) {
            subjects[index].name =
                clean(
                    req.body.name,
                    120
                );
        }

        if (req.body.code !== undefined) {
            subjects[index].code =
                clean(
                    req.body.code,
                    30
                );
        }

        write("subjects", subjects);

        res.json({
            success: true,
            subject:
                subjects[index]
        });
    }
);

app.delete(
    "/api/subjects/:id",
    auth,
    role("school_admin", "superadmin"),
    (req, res) => {
        const subjects =
            read("subjects");

        const subject =
            subjects.find(
                s =>
                    s.id ===
                    req.params.id
            );

        if (!subject) {
            return res.status(404).json({
                error:
                    "Subject not found."
            });
        }

        if (
            req.currentUser.role !==
                "superadmin" &&
            subject.schoolId !==
                req.currentUser.schoolId
        ) {
            return res.status(403).json({
                error:
                    "Access denied."
            });
        }

        write(
            "subjects",
            subjects.filter(
                s =>
                    s.id !==
                    req.params.id
            )
        );

        res.json({
            success: true
        });
    }
);

// ------------------------------------------------------------
// ANNOUNCEMENTS
// ------------------------------------------------------------

app.get(
    "/api/announcements",
    auth,
    (req, res) => {
        const announcements =
            read("announcements")
                .filter(
                    a =>
                        a.schoolId ===
                        req.currentUser.schoolId
                )
                .sort(
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
    auth,
    role("teacher", "school_admin", "superadmin"),
    (req, res) => {
        const title =
            clean(req.body.title, 150);

        const message =
            clean(req.body.message, 5000);

        if (!title || !message) {
            return res.status(400).json({
                error:
                    "Title and message are required."
            });
        }

        const announcements =
            read("announcements");

        const announcement = {
            id: uid("announcement_"),
            schoolId:
                req.currentUser.schoolId,
            title,
            message,
            authorId:
                req.currentUser.id,
            authorName:
                req.currentUser.fullName,
            createdAt: now()
        };

        announcements.push(
            announcement
        );

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
    auth,
    role("school_admin", "superadmin"),
    (req, res) => {
        const announcements =
            read("announcements");

        const item =
            announcements.find(
                a =>
                    a.id ===
                    req.params.id
            );

        if (!item) {
            return res.status(404).json({
                error:
                    "Announcement not found."
            });
        }

        if (
            req.currentUser.role !==
                "superadmin" &&
            item.schoolId !==
                req.currentUser.schoolId
        ) {
            return res.status(403).json({
                error:
                    "Access denied."
            });
        }

        write(
            "announcements",
            announcements.filter(
                a =>
                    a.id !==
                    req.params.id
            )
        );

        res.json({
            success: true
        });
    }
);

// ------------------------------------------------------------
// EXAMS
// ------------------------------------------------------------

app.get(
    "/api/exams",
    auth,
    (req, res) => {
        const exams =
            read("exams")
                .filter(
                    e =>
                        e.schoolId ===
                        req.currentUser.schoolId
                )
                .map(exam => {
                    const subject =
                        subjectOf(
                            exam.subjectId
                        );

                    const questionCount =
                        questionsOf(
                            exam.id
                        ).length;

                    const submissionCount =
                        read("results")
                            .filter(
                                r =>
                                    r.examId ===
                                    exam.id
                            ).length;

                    return {
                        ...exam,
                        subjectName:
                            subject
                                ? subject.name
                                : "Unknown",
                        questionCount,
                        submissionCount
                    };
                });

        res.json({
            exams
        });
    }
);

app.get(
    "/api/exams/:id",
    auth,
    (req, res) => {
        const exam =
            examOf(req.params.id);

        if (!exam) {
            return res.status(404).json({
                error:
                    "Exam not found."
            });
        }

        if (
            exam.schoolId !==
            req.currentUser.schoolId
        ) {
            return res.status(403).json({
                error:
                    "Access denied."
            });
        }

        res.json({
            exam
        });
    }
);

app.post(
    "/api/exams",
    auth,
    role("teacher", "school_admin", "superadmin"),
    (req, res) => {
        const title =
            clean(req.body.title, 200);

        const subjectId =
            clean(req.body.subjectId);

        const duration =
            Math.max(
                1,
                Number(
                    req.body.duration || 30
                )
            );

        const instructions =
            clean(
                req.body.instructions,
                5000
            );

        if (!title || !subjectId) {
            return res.status(400).json({
                error:
                    "Exam title and subject are required."
            });
        }

        const subject =
            subjectOf(subjectId);

        if (
            !subject ||
            subject.schoolId !==
                req.currentUser.schoolId
        ) {
            return res.status(400).json({
                error:
                    "Invalid subject."
            });
        }

        const exams =
            read("exams");

        const exam = {
            id: uid("exam_"),
            schoolId:
                req.currentUser.schoolId,
            subjectId,
            title,
            duration,
            instructions,
            status:
                req.body.status ===
                "published"
                    ? "published"
                    : "draft",
            createdBy:
                req.currentUser.id,
            createdAt: now()
        };

        exams.push(exam);

        write("exams", exams);

        res.json({
            success: true,
            exam
        });
    }
);

app.put(
    "/api/exams/:id",
    auth,
    role("teacher", "school_admin", "superadmin"),
    (req, res) => {
        const exams =
            read("exams");

        const index =
            exams.findIndex(
                e =>
                    e.id ===
                    req.params.id
            );

        if (index === -1) {
            return res.status(404).json({
                error:
                    "Exam not found."
            });
        }

        if (
            exams[index].schoolId !==
            req.currentUser.schoolId
        ) {
            return res.status(403).json({
                error:
                    "Access denied."
            });
        }

        if (req.body.title !== undefined) {
            exams[index].title =
                clean(
                    req.body.title,
                    200
                );
        }

        if (
            req.body.duration !==
            undefined
        ) {
            exams[index].duration =
                Math.max(
                    1,
                    Number(
                        req.body.duration
                    )
                );
        }

        if (
            req.body.instructions !==
            undefined
        ) {
            exams[index].instructions =
                clean(
                    req.body.instructions,
                    5000
                );
        }

        if (
            req.body.status !==
            undefined &&
            [
                "draft",
                "published",
                "closed"
            ].includes(
                req.body.status
            )
        ) {
            exams[index].status =
                req.body.status;
        }

        exams[index].updatedAt = now();

        write("exams", exams);

        res.json({
            success: true,
            exam:
                exams[index]
        });
    }
);

app.delete(
    "/api/exams/:id",
    auth,
    role("teacher", "school_admin", "superadmin"),
    (req, res) => {
        const exam =
            examOf(req.params.id);

        if (!exam) {
            return res.status(404).json({
                error:
                    "Exam not found."
            });
        }

        if (
            exam.schoolId !==
            req.currentUser.schoolId
        ) {
            return res.status(403).json({
                error:
                    "Access denied."
            });
        }

        write(
            "exams",
            read("exams").filter(
                e =>
                    e.id !==
                    req.params.id
            )
        );

        write(
            "questions",
            read("questions").filter(
                q =>
                    q.examId !==
                    req.params.id
            )
        );

        write(
            "results",
            read("results").filter(
                r =>
                    r.examId !==
                    req.params.id
            )
        );

        res.json({
            success: true
        });
    }
);

// ------------------------------------------------------------
// QUESTIONS
// ------------------------------------------------------------

app.get(
    "/api/exams/:id/questions",
    auth,
    role(
        "teacher",
        "school_admin",
        "superadmin"
    ),
    (req, res) => {
        const exam =
            examOf(req.params.id);

        if (!exam) {
            return res.status(404).json({
                error:
                    "Exam not found."
            });
        }

        if (
            exam.schoolId !==
            req.currentUser.schoolId
        ) {
            return res.status(403).json({
                error:
                    "Access denied."
            });
        }

        res.json({
            questions:
                questionsOf(
                    exam.id
                )
        });
    }
);

app.post(
    "/api/exams/:id/questions",
    auth,
    role(
        "teacher",
        "school_admin",
        "superadmin"
    ),
    (req, res) => {
        const exam =
            examOf(req.params.id);

        if (!exam) {
            return res.status(404).json({
                error:
                    "Exam not found."
            });
        }

        if (
            exam.schoolId !==
            req.currentUser.schoolId
        ) {
            return res.status(403).json({
                error:
                    "Access denied."
            });
        }

        const question =
            clean(
                req.body.question,
                5000
            );

        const options =
            Array.isArray(
                req.body.options
            )
                ? req.body.options.map(
                    o =>
                        clean(
                            o,
                            1000
                        )
                )
                : [];

        const answer =
            Number(
                req.body.answer
            );

        if (
            !question ||
            options.length < 2 ||
            !Number.isInteger(answer) ||
            answer < 0 ||
            answer >= options.length
        ) {
            return res.status(400).json({
                error:
                    "Invalid question data."
            });
        }

        const questions =
            read("questions");

        const item = {
            id: uid("question_"),
            examId: exam.id,
            schoolId:
                exam.schoolId,
            question,
            options,
            answer,
            points:
                Number(
                    req.body.points || 1
                ),
            difficulty:
                clean(
                    req.body.difficulty,
                    50
                ) || "medium",
            tags:
                clean(
                    req.body.tags,
                    300
                ),
            createdAt: now()
        };

        questions.push(item);

        write(
            "questions",
            questions
        );

        res.json({
            success: true,
            question: item
        });
    }
);

// ------------------------------------------------------------
// BULK QUESTION BANK
// ------------------------------------------------------------

app.post(
    "/api/question-bank/bulk",
    auth,
    role(
        "teacher",
        "school_admin",
        "superadmin"
    ),
    (req, res) => {
        const examId =
            clean(req.body.examId);

        const items =
            Array.isArray(
                req.body.questions
            )
                ? req.body.questions
                : [];

        const exam =
            examOf(examId);

        if (!exam) {
            return res.status(404).json({
                error:
                    "Exam not found."
            });
        }

        if (
            exam.schoolId !==
            req.currentUser.schoolId
        ) {
            return res.status(403).json({
                error:
                    "Access denied."
            });
        }

        if (!items.length) {
            return res.status(400).json({
                error:
                    "No questions supplied."
            });
        }

        const questions =
            read("questions");

        let added = 0;

        for (const item of items) {
            const question =
                clean(
                    item.question,
                    5000
                );

            const options =
                Array.isArray(
                    item.options
                )
                    ? item.options.map(
                        o =>
                            clean(
                                o,
                                1000
                            )
                    )
                    : [];

            const answer =
                Number(item.answer);

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
                id:
                    uid("question_"),
                examId,
                schoolId:
                    exam.schoolId,
                question,
                options,
                answer,
                points:
                    Number(
                        item.points || 1
                    ),
                difficulty:
                    clean(
                        item.difficulty,
                        50
                    ) || "medium",
                tags:
                    clean(
                        item.tags,
                        300
                    ),
                createdAt: now()
            });

            added++;
        }

        write(
            "questions",
            questions
        );

        res.json({
            success: true,
            added
        });
    }
);

// ------------------------------------------------------------
// QUESTION BANK
// ------------------------------------------------------------

app.get(
    "/api/question-bank",
    auth,
    role(
        "teacher",
        "school_admin",
        "superadmin"
    ),
    (req, res) => {
        let questions =
            read("questions")
                .filter(
                    q =>
                        q.schoolId ===
                        req.currentUser.schoolId
                );

        const search =
            clean(
                req.query.search,
                200
            ).toLowerCase();

        if (search) {
            questions =
                questions.filter(
                    q =>
                        q.question
                            .toLowerCase()
                            .includes(search) ||
                        String(
                            q.tags || ""
                        )
                            .toLowerCase()
                            .includes(search)
                );
        }

        if (req.query.examId) {
            questions =
                questions.filter(
                    q =>
                        q.examId ===
                        req.query.examId
                );
        }

        res.json({
            questions
        });
    }
);

// ------------------------------------------------------------
// STUDENT EXAM TAKE
// ------------------------------------------------------------

app.get(
    "/api/exams/:id/take",
    auth,
    role("student"),
    (req, res) => {
        const exam =
            examOf(req.params.id);

        if (!exam) {
            return res.status(404).json({
                error:
                    "Exam not found."
            });
        }

        if (
            exam.schoolId !==
            req.currentUser.schoolId
        ) {
            return res.status(403).json({
                error:
                    "Access denied."
            });
        }

        if (
            exam.status !==
            "published"
        ) {
            return res.status(400).json({
                error:
                    "This exam is not currently available."
            });
        }

        const questions =
            questionsOf(exam.id)
                .map(q => ({
                    id: q.id,
                    question:
                        q.question,
                    options:
                        q.options,
                    points:
                        q.points
                }));

        res.json({
            exam,
            questions
        });
    }
);

// ------------------------------------------------------------
// SUBMIT EXAM
// ------------------------------------------------------------

app.post(
    "/api/exams/:id/submit",
    auth,
    role("student"),
    (req, res) => {
        const exam =
            examOf(req.params.id);

        if (!exam) {
            return res.status(404).json({
                error:
                    "Exam not found."
            });
        }

        if (
            exam.schoolId !==
            req.currentUser.schoolId
        ) {
            return res.status(403).json({
                error:
                    "Access denied."
            });
        }

        const answers =
            req.body.answers || {};

        const questions =
            questionsOf(exam.id);

        let score = 0;
        let total = 0;

        const answerDetails = [];

        for (const q of questions) {
            const points =
                Number(q.points || 1);

            total += points;

            const submitted =
                answers[q.id];

            const correct =
                Number(submitted) ===
                Number(q.answer);

            if (correct) {
                score += points;
            }

            answerDetails.push({
                questionId: q.id,
                answer:
                    submitted !== undefined
                        ? Number(submitted)
                        : null,
                correct
            });
        }

        const percentage =
            total > 0
                ? Math.round(
                    (score / total) *
                    100
                )
                : 0;

        const results =
            read("results");

        const existing =
            results.find(
                r =>
                    r.examId ===
                        exam.id &&
                    r.studentId ===
                        req.currentUser.id
            );

        if (existing) {
            return res.status(409).json({
                error:
                    "You have already submitted this exam.",
                result: existing
            });
        }

        const result = {
            id: uid("result_"),
            examId: exam.id,
            schoolId:
                exam.schoolId,
            studentId:
                req.currentUser.id,
            studentName:
                req.currentUser.fullName,
            score,
            total,
            percentage,
            answers:
                answerDetails,
            submittedAt: now()
        };

        results.push(result);

        write(
            "results",
            results
        );

        res.json({
            success: true,
            result
        });
    }
);

// ------------------------------------------------------------
// RESULTS
// ------------------------------------------------------------

app.get(
    "/api/results",
    auth,
    (req, res) => {
        let results =
            read("results")
                .filter(
                    r =>
                        r.schoolId ===
                        req.currentUser.schoolId
                );

        if (
            req.currentUser.role ===
            "student"
        ) {
            results =
                results.filter(
                    r =>
                        r.studentId ===
                        req.currentUser.id
                );
        }

        results =
            results.map(r => ({
                ...r,
                examTitle:
                    examOf(r.examId)
                        ? examOf(r.examId).title
                        : "Unknown Exam"
            }));

        res.json({
            results
        });
    }
);

app.get(
    "/api/results/:id",
    auth,
    (req, res) => {
        const result =
            read("results").find(
                r =>
                    r.id ===
                    req.params.id
            );

        if (!result) {
            return res.status(404).json({
                error:
                    "Result not found."
            });
        }

        if (
            result.schoolId !==
            req.currentUser.schoolId
        ) {
            return res.status(403).json({
                error:
                    "Access denied."
            });
        }

        if (
            req.currentUser.role ===
                "student" &&
            result.studentId !==
                req.currentUser.id
        ) {
            return res.status(403).json({
                error:
                    "Access denied."
            });
        }

        res.json({
            result
        });
    }
);

// ------------------------------------------------------------
// SUPERADMIN - SCHOOLS
// ------------------------------------------------------------

app.get(
    "/api/superadmin/schools",
    auth,
    role("superadmin"),
    (req, res) => {
        res.json({
            schools:
                read("schools")
        });
    }
);

app.post(
    "/api/superadmin/schools",
    auth,
    role("superadmin"),
    (req, res) => {
        const name =
            clean(req.body.name, 150);

        if (!name) {
            return res.status(400).json({
                error:
                    "School name is required."
            });
        }

        const schools =
            read("schools");

        const school = {
            id: uid("school_"),
            name,
            motto:
                clean(
                    req.body.motto,
                    250
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
            theme:
                ["light", "dark"].includes(
                    req.body.theme
                )
                    ? req.body.theme
                    : "light",
            active: true,
            createdAt: now()
        };

        schools.push(school);

        write(
            "schools",
            schools
        );

        res.json({
            success: true,
            school
        });
    }
);

app.put(
    "/api/superadmin/schools/:id",
    auth,
    role("superadmin"),
    (req, res) => {
        const schools =
            read("schools");

        const index =
            schools.findIndex(
                s =>
                    s.id ===
                    req.params.id
            );

        if (index === -1) {
            return res.status(404).json({
                error:
                    "School not found."
            });
        }

        const school =
            schools[index];

        if (req.body.name !== undefined) {
            school.name =
                clean(
                    req.body.name,
                    150
                );
        }

        if (req.body.motto !== undefined) {
            school.motto =
                clean(
                    req.body.motto,
                    250
                );
        }

        if (req.body.active !== undefined) {
            school.active =
                Boolean(
                    req.body.active
                );
        }

        school.updatedAt = now();

        write(
            "schools",
            schools
        );

        res.json({
            success: true,
            school
        });
    }
);

// ------------------------------------------------------------
// SUPERADMIN - ALL USERS
// ------------------------------------------------------------

app.get(
    "/api/superadmin/all-users",
    auth,
    role("superadmin"),
    (req, res) => {
        res.json({
            users:
                read("users").map(
                    safeUser
                )
        });
    }
);

// ------------------------------------------------------------
// MULTER ERROR HANDLER
// ------------------------------------------------------------

app.use(
    (error, req, res, next) => {
        if (
            error instanceof multer.MulterError
        ) {
            return res.status(400).json({
                error:
                    error.message
            });
        }

        if (error) {
            console.error(
                "SERVER ERROR",
                error
            );

            if (
                req.path.startsWith(
                    "/api/"
                )
            ) {
                return res.status(500).json({
                    error:
                        error.message ||
                        "Server error"
                });
            }

            return res.status(500).send(
                "Internal server error"
            );
        }

        next();
    }
);

// ------------------------------------------------------------
// API 404
// ------------------------------------------------------------

app.use(
    "/api",
    (req, res) => {
        res.status(404).json({
            error:
                "API endpoint not found",
            path: req.path
        });
    }
);

// ------------------------------------------------------------
// FRONTEND FALLBACK
// ------------------------------------------------------------

app.get(
    "*",
    (req, res) => {
        const index =
            path.join(
                ROOT,
                "public",
                "index.html"
            );

        if (fs.existsSync(index)) {
            return res.sendFile(index);
        }

        res.status(404).send(
            "SchoolHub Pro frontend not found."
        );
    }
);

// ------------------------------------------------------------
// START SERVER
// ------------------------------------------------------------

const server =
    app.listen(
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
                "Server listening on 0.0.0.0"
            );
            console.log(
                "========================================"
            );
        }
    );

// ------------------------------------------------------------
// GRACEFUL RAILWAY SHUTDOWN
// ------------------------------------------------------------

let shuttingDown = false;

function shutdown(signal) {
    if (shuttingDown) return;

    shuttingDown = true;

    console.log(
        `Received ${signal}. Shutting down gracefully...`
    );

    server.close(() => {
        console.log(
            "HTTP server closed."
        );

        process.exit(0);
    });

    setTimeout(() => {
        console.log(
            "Forced shutdown after timeout."
        );

        process.exit(0);
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
