const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();

app.use(express.json());
app.use(cors());

app.use(express.static(path.join(__dirname)));

// ================= MYSQL CONNECTION (CLOUD & LOCAL READY) =================
const db = mysql.createConnection({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "mamed_food",
    port: process.env.DB_PORT || 3306
});

db.connect((err) => {
    if (err) {
        console.log("DB connection error:", err);
    } else {
        console.log("MySQL connected successfully");
    }
});

// ================= İTİS AUDIT LOG FUNKSİYASI =================
function logAudit(username, action, status, req) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    const query = "INSERT INTO audit_logs (username, action, status, ip_address) VALUES (?, ?, ?, ?)";
    db.query(query, [username || 'ANONYMOUS', action, status, ip], (err) => {
        if (err) console.log("Audit log xətası:", err);
    });
}

// ================= REGISTER =================
app.post("/register", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Boş xana ola bilməz" });
    }

    db.query(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, result) => {
            if (err) {
                console.log(err);
                return res.json({ success: false, message: "DB error" });
            }

            if (result.length > 0) {
                logAudit(username, "REGISTER", "FAILED_USER_EXISTS", req);
                return res.json({ success: false, message: "İstifadəçi artıq var" });
            }

            try {
                const hashedPassword = await bcrypt.hash(password, 10);

                db.query(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    [username, hashedPassword],
                    (err) => {
                        if (err) {
                            console.log(err);
                            return res.json({ success: false, message: "Insert error" });
                        }

                        logAudit(username, "REGISTER", "SUCCESS", req);
                        res.json({ success: true });
                    }
                );
            } catch (e) {
                console.log(e);
                res.json({ success: false, message: "Hash error" });
            }
        }
    );
});

// ================= LOGIN =================
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Boş xana ola bilməz" });
    }

    db.query(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, result) => {
            if (err) {
                console.log(err);
                return res.json({ success: false, message: "DB error" });
            }

            if (result.length === 0) {
                logAudit(username, "LOGIN", "FAILED_USER_NOT_FOUND", req);
                return res.json({ success: false, message: "İstifadəçi tapılmadı" });
            }

            const user = result[0];

            try {
                const isMatch = await bcrypt.compare(password, user.password);

                if (!isMatch) {
                    logAudit(username, "LOGIN", "FAILED_WRONG_PASSWORD", req);
                    return res.json({ success: false, message: "Şifrə yanlışdır" });
                }

                logAudit(username, "LOGIN", "SUCCESS", req);
                return res.json({ success: true });

            } catch (e) {
                console.log(e);
                return res.json({ success: false, message: "Compare error" });
            }
        }
    );
});

// ================= ROUTES =================
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/mamedfood", (req, res) => {
    res.sendFile(path.join(__dirname, "mamedfood.html"));
});

// İTİS AUDIT LOGS ENDPOINT-İ
app.get("/api/audit-logs", (req, res) => {
    db.query("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 50", (err, results) => {
        if (err) return res.json({ success: false, error: err });
        res.json({ success: true, logs: results });
    });
});

// ================= START SERVER =================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT} - Audit Logs Active!`);
});