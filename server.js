import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import multer from "multer";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET =
  process.env.JWT_SECRET || "change-this-secret-in-production";

const DB_PATH =
  process.env.DB_PATH || path.join(__dirname, "business-exception.db");

const db = new Database(DB_PATH);

const uploadDir = path.join(__dirname, "uploads");

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

app.use(
  express.static(path.join(__dirname, "public"))
);

const upload = multer({
  dest: uploadDir,
  limits: {
    fileSize: 10 * 1024 * 1024
  }
});

/* ---------------- DATABASE ---------------- */

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS workspaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    filename TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS exceptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    workspace_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    customer TEXT,
    reference TEXT,
    amount REAL,
    total REAL,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN',
    note TEXT,
    created_at TEXT NOT NULL
  );
`);

/* ---------------- HELPERS ---------------- */

const now = () => new Date().toISOString();

function hash(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
}

function token(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function auth(req, res, next) {
  try {
    const t = req.cookies.bed_session;

    if (!t) {
      return res.status(401).json({
        error: "Authentication required"
      });
    }

    const user = jwt.verify(t, JWT_SECRET);

    req.user = user;

    next();
  } catch (err) {
    return res.status(401).json({
      error: "Authentication required"
    });
  }
}

function getWorkspace(userId) {
  return db
    .prepare(
      "SELECT * FROM workspaces WHERE owner_id = ? ORDER BY id LIMIT 1"
    )
    .get(userId);
}

/* ---------------- CSV PARSER ---------------- */

function parseCSV(text) {
  const lines = text
    .split(/\r?\n/)
    .filter((x) => x.trim());

  if (!lines.length) {
    return [];
  }

  function parseLine(line) {
    const result = [];
    let current = "";
    let quoted = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];

      if (char === '"') {
        if (quoted && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          quoted = !quoted;
        }
      } else if (char === "," && !quoted) {
        result.push(current);
        current = "";
      } else {
        current += char;
      }
    }

    result.push(current);

    return result;
  }

  const headers = parseLine(lines[0]).map((x) =>
    x.trim().toLowerCase()
  );

  return lines.slice(1).map((line) => {
    const values = parseLine(line);
    const row = {};

    headers.forEach((header, index) => {
      row[header] = (values[index] || "").trim();
    });

    return row;
  });
}

function find(row, keys) {
  for (const key of keys) {
    const value = row[key];

    if (
      value !== undefined &&
      value !== null &&
      String(value).trim() !== ""
    ) {
      return String(value).trim();
    }
  }

  return "";
}

function num(value) {
  if (value === undefined || value === null) {
    return 0;
  }

  const cleaned = String(value)
    .replace(/[£$,]/g, "")
    .replace(/\s/g, "");

  const result = Number(cleaned);

  return Number.isFinite(result) ? result : 0;
}

/* ---------------- EXCEPTION DETECTOR ---------------- */

function detect(rows) {
  const output = [];

  /*
    Detect duplicate invoice references
  */

  const references = new Map();

  rows.forEach((row, index) => {
    const reference = find(row, [
      "invoiceno",
      "invoice_no",
      "invoice",
      "reference",
      "invoice number",
      "invoice_number"
    ]);

    if (!reference) {
      return;
    }

    if (!references.has(reference)) {
      references.set(reference, []);
    }

    references.get(reference).push(index);
  });

  references.forEach((indexes, reference) => {
    if (indexes.length > 1) {
      indexes.forEach((index) => {
        const row = rows[index];

        output.push({
          type: "Duplicate",
          severity: "HIGH",
          customer: find(row, [
            "customer",
            "customername",
            "customer_name",
            "client"
          ]),
          reference,
          amount: num(
            find(row, [
              "amount",
              "invoiceamount",
              "invoice_amount"
            ])
          ),
          total: num(
            find(row, [
              "total",
              "invoicetotal",
              "invoice_total"
            ])
          ),
          reason:
            "The invoice reference matches another invoice."
        });
      });
    }
  });

  /*
    Detect payment differences
  */

  rows.forEach((row) => {
    const total = num(
      find(row, [
        "total",
        "invoicetotal",
        "invoice_total",
        "amount"
      ])
    );

    const paid = num(
      find(row, [
        "paid",
        "paidamount",
        "paid_amount",
        "payment",
        "paymentamount",
        "payment_amount"
      ])
    );

    if (total > 0 && paid >= 0) {
      const difference = total - paid;

      if (difference > 0.01) {
        output.push({
          type: "Payment",
          severity: difference > 100 ? "HIGH" : "MEDIUM",
          customer: find(row, [
            "customer",
            "customername",
            "customer_name",
            "client"
          ]),
          reference: find(row, [
            "invoiceno",
            "invoice_no",
            "invoice",
            "reference",
            "invoice number",
            "invoice_number"
          ]),
          amount: paid,
          total,
          reason:
            `Payment is £${difference.toFixed(2)} below the invoice total.`
        });
      }
    }
  });

  return output;
}

/* ---------------- SIGNUP ---------------- */

app.post("/api/signup", (req, res) => {
  const email = String(req.body?.email || "")
    .trim()
    .toLowerCase();

  const password = String(req.body?.password || "");

  if (!email || !email.includes("@")) {
    return res.status(400).json({
      error: "Please enter a valid email address."
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      error: "Password must be at least 8 characters."
    });
  }

  try {
    const passwordHash = hash(password);

    const info = db
      .prepare(
        `
        INSERT INTO users
        (email, password_hash, created_at)
        VALUES (?, ?, ?)
        `
      )
      .run(email, passwordHash, now());

    const userId = Number(info.lastInsertRowid);

    const workspace = db
      .prepare(
        `
        INSERT INTO workspaces
        (owner_id, name, created_at)
        VALUES (?, ?, ?)
        `
      )
      .run(userId, "My Workspace", now());

    const user = {
      id: userId,
      email
    };

    res.cookie(
      "bed_session",
      token(user),
      {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        maxAge: 7 * 24 * 60 * 60 * 1000
      }
    );

    return res.json({
      user,
      workspaceId: Number(workspace.lastInsertRowid)
    });
  } catch (err) {
    if (
      String(err.message).includes("UNIQUE") ||
      String(err.message).includes("users.email")
    ) {
      return res.status(409).json({
        error: "An account with that email already exists."
      });
    }

    console.error("Signup error:", err);

    return res.status(500).json({
      error: "Could not create account."
    });
  }
});

/* ---------------- LOGIN ---------------- */

app.post("/api/login", (req, res) => {
  const email = String(req.body?.email || "")
    .trim()
    .toLowerCase();

  const password = String(req.body?.password || "");

  if (!email || !password) {
    return res.status(400).json({
      error: "Email and password are required."
    });
  }

  try {
    const user = db
      .prepare(
        `
        SELECT *
        FROM users
        WHERE email = ?
        `
      )
      .get(email);

    if (!user || hash(password) !== user.password_hash) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const safeUser = {
      id: user.id,
      email: user.email
    };

    res.cookie(
      "bed_session",
      token(safeUser),
      {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        maxAge: 7 * 24 * 60 * 60 * 1000
      }
    );

    return res.json({
      user: safeUser
    });
  } catch (err) {
    console.error("Login error:", err);

    return res.status(500).json({
      error: "Could not log in."
    });
  }
});

/* ---------------- LOGOUT ---------------- */

app.post("/api/logout", (req, res) => {
  res.clearCookie("bed_session");

  res.json({
    ok: true
  });
});

/* ---------------- CURRENT USER ---------------- */

app.get("/api/me", auth, (req, res) => {
  const workspace = getWorkspace(req.user.id);

  res.json({
    user: req.user,
    workspace
  });
});

/* ---------------- SCAN CSV ---------------- */

app.post(
  "/api/scans",
  auth,
  upload.single("file"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        error: "Please upload a CSV file."
      });
    }

    const workspace = getWorkspace(req.user.id);

    if (!workspace) {
      return res.status(404).json({
        error: "Workspace not found."
      });
    }

    try {
      const text = fs.readFileSync(
        req.file.path,
        "utf8"
      );

      const rows = parseCSV(text);

      const issues = detect(rows);

      const scan = db
        .prepare(
          `
          INSERT INTO scans
          (workspace_id, filename, created_at)
          VALUES (?, ?, ?)
          `
        )
        .run(
          workspace.id,
          req.file.originalname,
          now()
        );

      const scanId = Number(scan.lastInsertRowid);

      const insertException = db.prepare(`
        INSERT INTO exceptions
        (
          scan_id,
          workspace_id,
          type,
          severity,
          customer,
          reference,
          amount,
          total,
          reason,
          status,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?)
      `);

      const insertMany = db.transaction((items) => {
        for (const issue of items) {
          insertException.run(
            scanId,
            workspace.id,
            issue.type,
            issue.severity,
            issue.customer || "",
            issue.reference || "",
            issue.amount || 0,
            issue.total || 0,
            issue.reason || "",
            now()
          );
        }
      });

      insertMany(issues);

      fs.unlinkSync(req.file.path);

      return res.json({
        scanId,
        exceptionsFound: issues.length,
        exceptions: issues
      });
    } catch (err) {
      console.error("Scan error:", err);

      try {
        if (fs.existsSync(req.file.path)) {
          fs.unlinkSync(req.file.path);
        }
      } catch {}

      return res.status(500).json({
        error: "Could not process the file."
      });
    }
  }
);

/* ---------------- SCANS ---------------- */

app.get("/api/scans", auth, (req, res) => {
  const workspace = getWorkspace(req.user.id);

  if (!workspace) {
    return res.status(404).json({
      error: "Workspace not found."
    });
  }

  const scans = db
    .prepare(
      `
      SELECT *
      FROM scans
      WHERE workspace_id = ?
      ORDER BY id DESC
      `
    )
    .all(workspace.id);

  res.json({
    scans
  });
});

/* ---------------- EXCEPTIONS ---------------- */

app.get("/api/exceptions", auth, (req, res) => {
  const workspace = getWorkspace(req.user.id);

  if (!workspace) {
    return res.status(404).json({
      error: "Workspace not found."
    });
  }

  const exceptions = db
    .prepare(
      `
      SELECT *
      FROM exceptions
      WHERE workspace_id = ?
      ORDER BY id DESC
      `
    )
    .all(workspace.id);

  res.json({
    exceptions
  });
});

/* ---------------- UPDATE EXCEPTION ---------------- */

app.patch(
  "/api/exceptions/:id",
  auth,
  (req, res) => {
    const id = Number(req.params.id);

    const workspace = getWorkspace(req.user.id);

    if (!workspace) {
      return res.status(404).json({
        error: "Workspace not found."
      });
    }

    const exception = db
      .prepare(
        `
        SELECT id
        FROM exceptions
        WHERE id = ?
        AND workspace_id = ?
        `
      )
      .get(id, workspace.id);

    if (!exception) {
      return res.status(404).json({
        error: "Exception not found."
      });
    }

    const status =
      req.body?.status === "RESOLVED"
        ? "RESOLVED"
        : req.body?.status === "OPEN"
        ? "OPEN"
        : null;

    if (!status) {
      return res.status(400).json({
        error: "Invalid status."
      });
    }

    db.prepare(
      `
      UPDATE exceptions
      SET status = ?
      WHERE id = ?
      AND workspace_id = ?
      `
    ).run(
      status,
      id,
      workspace.id
    );

    res.json({
      ok: true
    });
  }
);

/* ---------------- ADD NOTE ---------------- */

app.patch(
  "/api/exceptions/:id/note",
  auth,
  (req, res) => {
    const id = Number(req.params.id);

    const workspace = getWorkspace(req.user.id);

    if (!workspace) {
      return res.status(404).json({
        error: "Workspace not found."
      });
    }

    const exception = db
      .prepare(
        `
        SELECT id
        FROM exceptions
        WHERE id = ?
        AND workspace_id = ?
        `
      )
      .get(id, workspace.id);

    if (!exception) {
      return res.status(404).json({
        error: "Exception not found."
      });
    }

    const note = String(
      req.body?.note || ""
    );

    db.prepare(
      `
      UPDATE exceptions
      SET note = ?
      WHERE id = ?
      AND workspace_id = ?
      `
    ).run(
      note,
      id,
      workspace.id
    );

    res.json({
      ok: true
    });
  }
);

/* ---------------- HEALTH CHECK ---------------- */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true
  });
});

/* ---------------- START ---------------- */

app.listen(PORT, () => {
  console.log(
    `Business Exception Detector running on port ${PORT}`
  );
});
