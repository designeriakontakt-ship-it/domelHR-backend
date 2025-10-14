const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'BARDZO_TAJNY_KLUCZ_KTORY_POWINIEN_BYC_DLUZSZY';

app.use(cors());
app.use(express.json());

// --- KONFIGURACJA BAZY DANYCH ---
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'domelhr_db',
  password: '&f;SyUwDRAd+MS(Wx3X7',
  port: 5432,
});

// --- Middleware autoryzacji ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const authorizeEmployer = (req, res, next) => {
  if (req.user.role !== 'employer') {
    return res.status(403).json({ error: 'Brak uprawnień. Dostęp tylko dla pracodawcy.' });
  }
  next();
};

// --- TEST ENDPOINT ---
app.get('/api/test', (req, res) => {
  res.json({ message: 'Serwer domelHR działa poprawnie!' });
});

// --- Rejestracja ---
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, full_name, invitationCode } = req.body;
    let role = 'employee';
    const EMPLOYER_SECRET_CODE = 'DOMEL-ADMIN-2025';
    if (invitationCode === EMPLOYER_SECRET_CODE) {
      role = 'employer';
    }

    if (!email || !password)
      return res.status(400).json({ error: 'Email i hasło są wymagane.' });

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, full_name, role) VALUES ($1, $2, $3, $4) RETURNING id, email, full_name, role',
      [email, passwordHash, full_name, role]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505')
      return res.status(409).json({ error: 'Użytkownik z tym adresem email już istnieje.' });
    res.status(500).json({ error: 'Błąd serwera podczas rejestracji.' });
  }
});

// --- Logowanie ---
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = userResult.rows[0];
    if (!user) return res.status(401).json({ error: 'Nieprawidłowy email lub hasło.' });

    const isCorrect = await bcrypt.compare(password, user.password_hash);
    if (!isCorrect) return res.status(401).json({ error: 'Nieprawidłowy email lub hasło.' });

    const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, role: user.role });
  } catch (err) {
    res.status(500).json({ error: 'Błąd serwera podczas logowania.' });
  }
});

// --- Lista pracowników (dla pracodawcy) ---
app.get('/api/employees', authenticateToken, authorizeEmployer, async (req, res) => {
  const result = await pool.query("SELECT id, full_name, email FROM users WHERE role = 'employee'");
  res.json(result.rows);
});

// --- Grafiki pracy ---
app.get('/api/schedule/my', authenticateToken, async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM work_schedules WHERE user_id = $1 ORDER BY start_time ASC',
    [req.user.userId]
  );
  res.json(result.rows);
});

app.post('/api/schedules', authenticateToken, authorizeEmployer, async (req, res) => {
  const { userId, startTime, endTime } = req.body;
  const result = await pool.query(
    'INSERT INTO work_schedules (user_id, start_time, end_time) VALUES ($1, $2, $3) RETURNING *',
    [userId, startTime, endTime]
  );
  res.status(201).json(result.rows[0]);
});

// --- Wnioski urlopowe ---
app.post('/api/leave-requests', authenticateToken, async (req, res) => {
  const { startDate, endDate, reason } = req.body;
  const result = await pool.query(
    'INSERT INTO leave_requests (user_id, start_date, end_date, reason) VALUES ($1, $2, $3, $4) RETURNING *',
    [req.user.userId, startDate, endDate, reason]
  );
  res.status(201).json(result.rows[0]);
});

app.get('/api/leave-requests/my', authenticateToken, async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM leave_requests WHERE user_id = $1 ORDER BY start_date DESC',
    [req.user.userId]
  );
  res.json(result.rows);
});

app.get('/api/leave-requests/pending', authenticateToken, authorizeEmployer, async (req, res) => {
  const result = await pool.query(
    `SELECT lr.*, u.full_name FROM leave_requests lr 
     JOIN users u ON lr.user_id = u.id 
     WHERE lr.status = 'pending' 
     ORDER BY lr.created_at ASC`
  );
  res.json(result.rows);
});

app.put('/api/leave-requests/:id/status', authenticateToken, authorizeEmployer, async (req, res) => {
  const result = await pool.query(
    'UPDATE leave_requests SET status = $1 WHERE id = $2 RETURNING *',
    [req.body.status, req.params.id]
  );
  res.json(result.rows[0]);
});

// --- Czas pracy ---
app.get('/api/time/status', authenticateToken, async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM time_entries WHERE user_id = $1 AND clock_out_time IS NULL LIMIT 1',
    [req.user.userId]
  );
  res.json(result.rows[0] || null);
});

app.post('/api/time/clock-in', authenticateToken, async (req, res) => {
  const result = await pool.query(
    'INSERT INTO time_entries (user_id, clock_in_time) VALUES ($1, NOW()) RETURNING *',
    [req.user.userId]
  );
  res.status(201).json(result.rows[0]);
});

app.put('/api/time/clock-out', authenticateToken, async (req, res) => {
  const result = await pool.query(
    'UPDATE time_entries SET clock_out_time = NOW() WHERE user_id = $1 AND clock_out_time IS NULL RETURNING *',
    [req.user.userId]
  );
  res.json(result.rows[0]);
});

// --- Uruchomienie serwera ---
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Serwer DomelHR działa i nasłuchuje na porcie ${PORT}`);
});
