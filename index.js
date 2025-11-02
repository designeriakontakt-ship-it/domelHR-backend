const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000; // Aplikacja działa na porcie 3000, Nginx przekierowuje z 80
const JWT_SECRET = 'kE7b#pZ9$sWq@L&tV8!xR2*c!@kompleksoweHasloDlaJWT'; // Użyj swojego silnego sekretu JWT

app.use(express.json());

const pool = new Pool({
  user: 'domelhr_user',
  host: 'localhost',
  database: 'domelhr_db',
  password: 'domel10', // WPISZ SWOJE HASŁO DO BAZY DANYCH
  port: 5432,
});

// --- Middlewares ("Strażnicy") ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

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

// --- Endpointy Testowe ---
app.get('/api/test', (req, res) => {
  res.json({ message: 'Serwer domelHR działa poprawnie!' });
});

// --- Endpointy Użytkowników ---
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, full_name, invitationCode } = req.body;
    let role = 'employee';
    const EMPLOYER_SECRET_CODE = 'DOMEL-ADMIN-2025';
    if (invitationCode === EMPLOYER_SECRET_CODE) {
      role = 'employer';
    }
    if (!email || !password) return res.status(400).json({ error: 'Email i hasło są wymagane.' });
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, full_name, role) VALUES ($1, $2, $3, $4) RETURNING id, email, full_name, role',
      [email, passwordHash, full_name, role]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Użytkownik z tym adresem email już istnieje.' });
    console.error('Błąd rejestracji:', err);
    res.status(500).json({ error: 'Błąd serwera podczas rejestracji.' });
  }
});

// Endpoint do logowania (bez zmian od ostatniej wersji)
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = userResult.rows[0];
    if (!user) return res.status(401).json({ error: 'Nieprawidłowy email lub hasło.' });
    const isCorrect = await bcrypt.compare(password, user.password_hash);
    if (!isCorrect) return res.status(401).json({ error: 'Nieprawidłowy email lub hasło.' });
    const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token: token, role: user.role });
  } catch (err) {
    console.error('Błąd logowania:', err);
    res.status(500).json({ error: 'Błąd serwera podczas logowania.' });
  }
});

// Endpoint pobierania pracowników (bez zmian)
app.get('/api/employees', authenticateToken, authorizeEmployer, async (req, res) => {
    try {
        const result = await pool.query("SELECT id, full_name, email, default_start_time, default_end_time FROM users WHERE role = 'employee' ORDER BY full_name ASC");
        res.json(result.rows);
    } catch (error) {
        console.error('Błąd pobierania pracowników:', error);
        res.status(500).json({ error: 'Błąd pobierania pracowników' });
    }
});

// --- Endpointy Grafiku ---

// OSTATECZNA, POPRAWIONA WERSJA GET /api/schedule/my
app.get('/api/schedule/my', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const year = parseInt(req.query.year) || new Date().getFullYear();
    const month = parseInt(req.query.month) || new Date().getMonth() + 1;

    // --- OBLICZ LICZBĘ DNI W MIESIĄCU NAJPIERW ---
    const daysInMonth = new Date(year, month, 0).getDate(); // Poprawione miejsce deklaracji

    // --- Pobieranie danych ---
    const userSettings = await pool.query('SELECT default_start_time, default_end_time FROM users WHERE id = $1', [userId]);
    if (userSettings.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono użytkownika' });
    const { default_start_time, default_end_time } = userSettings.rows[0];

    const exceptionsResult = await pool.query(
      `SELECT id, start_time, end_time FROM work_schedules
       WHERE user_id = $1 AND EXTRACT(YEAR FROM start_time) = $2 AND EXTRACT(MONTH FROM start_time) = $3`,
      [userId, year, month]
    );
    const exceptions = exceptionsResult.rows.reduce((acc, row) => {
        const date = new Date(row.start_time).toLocaleDateString('sv-SE');
        acc[date] = row;
        return acc;
    }, {});

    const timeChangesResult = await pool.query(
        `SELECT id, work_date, requested_start_time, requested_end_time
         FROM time_change_requests
         WHERE user_id = $1 AND status = 'approved' AND EXTRACT(YEAR FROM work_date) = $2 AND EXTRACT(MONTH FROM work_date) = $3`,
        [userId, year, month]
    );
    const approvedChanges = timeChangesResult.rows.reduce((acc, row) => {
        const date = new Date(row.work_date).toLocaleDateString('sv-SE');
        acc[date] = row;
        return acc;
    }, {});

    // --- POPRAWIONE Pobieranie i przetwarzanie urlopów (z poprawnym zapytaniem) ---
    const leaveResult = await pool.query(
        `SELECT start_date, end_date FROM leave_requests
         WHERE user_id = $1 AND status = 'approved'
         AND start_date <= $3 -- Urlop zaczyna się w tym miesiącu lub wcześniej
         AND end_date >= $2 -- Urlop kończy się w tym miesiącu lub później
        `,
        [
            userId,
            `${year}-${String(month).padStart(2, '0')}-01`, // Pierwszy dzień miesiąca (YYYY-MM-DD)
            `${year}-${String(month).padStart(2, '0')}-${String(daysInMonth).padStart(2, '0')}` // Ostatni dzień miesiąca (YYYY-MM-DD)
        ]
    );

    const leaveDates = new Set();
    leaveResult.rows.forEach(leave => {
        let currentLeaveDate = new Date(Date.UTC(
             new Date(leave.start_date).getUTCFullYear(),
             new Date(leave.start_date).getUTCMonth(),
             new Date(leave.start_date).getUTCDate()
        ));
        const endLeaveDate = new Date(Date.UTC(
             new Date(leave.end_date).getUTCFullYear(),
             new Date(leave.end_date).getUTCMonth(),
             new Date(leave.end_date).getUTCDate()
        ));

        while (currentLeaveDate <= endLeaveDate) {
            if (currentLeaveDate.getUTCFullYear() === year && currentLeaveDate.getUTCMonth() === month - 1) {
                leaveDates.add(currentLeaveDate.toLocaleDateString('sv-SE'));
            }
            currentLeaveDate.setUTCDate(currentLeaveDate.getUTCDate() + 1);
        }
    });
    console.log(`[${year}-${month}] Znaleziono ${leaveDates.size} dni urlopowych.`);

    // --- Generowanie grafiku (z użyciem Set, bez zmian w logice) ---
    const schedule = [];
    // Już nie potrzebujemy tu obliczać daysInMonth
    for (let day = 1; day <= daysInMonth; day++) {
        const currentDate = new Date(Date.UTC(year, month - 1, day));
        const dateString = currentDate.toLocaleDateString('sv-SE');
        const dayOfWeek = currentDate.getUTCDay();
        let entry = null;

        if (leaveDates.has(dateString)) {
            entry = { id: `leave-${dateString}`, date: dateString, is_leave: true };
        } else {
            let baseStartTime = null;
            let baseEndTime = null;
            let isException = false;

            if (exceptions[dateString]) {
                  baseStartTime = exceptions[dateString].start_time;
                  baseEndTime = exceptions[dateString].end_time;
                  isException = true;
             } else if (default_start_time && default_end_time && dayOfWeek !== 0 && dayOfWeek !== 6) {
                  baseStartTime = new Date(`${dateString}T${default_start_time}Z`);
                  baseEndTime = new Date(`${dateString}T${default_end_time}Z`);
             }

             if (baseStartTime && baseEndTime && !isNaN(new Date(baseStartTime)) && !isNaN(new Date(baseEndTime))) {
                    let finalStartTime = baseStartTime instanceof Date ? baseStartTime : new Date(baseStartTime);
                    let finalEndTime = baseEndTime instanceof Date ? baseEndTime : new Date(baseEndTime);
                    let isApprovedChange = false;

                    if (approvedChanges[dateString]) {
                         const change = approvedChanges[dateString];
                         isApprovedChange = true;
                         if (change.requested_start_time) {
                              const requestedStart = new Date(`${dateString}T${change.requested_start_time}Z`);
                              if (!isNaN(requestedStart)) finalStartTime = requestedStart;
                         }
                         if (change.requested_end_time) {
                              const requestedEnd = new Date(`${dateString}T${change.requested_end_time}Z`);
                              if (!isNaN(requestedEnd)) finalEndTime = requestedEnd;
                         }
                    }

                    if (!isNaN(finalStartTime) && !isNaN(finalEndTime)) {
                        entry = {
                             id: isApprovedChange ? `chg-${approvedChanges[dateString].id}` : (isException ? `exc-${exceptions[dateString].id}` : `def-${dateString}`),
                             date: dateString, start_time: finalStartTime.toISOString(), end_time: finalEndTime.toISOString(),
                             is_exception: isException, is_approved_change: isApprovedChange, is_leave: false
                        };
                    } else { console.warn(`Nie udało się utworzyć finalnej daty dla ${dateString}`); }
             } else if (!exceptions[dateString] && (dayOfWeek === 0 || dayOfWeek === 6)) {
                  // Opcjonalnie wpis dla weekendu
             } else if(baseStartTime || baseEndTime) {
                  console.warn(`Nie udało się utworzyć bazowej daty dla ${dateString}`);
             }
        } // Koniec 'else' po urlopie

        if (entry) {
            schedule.push(entry);
        }
    } // Koniec pętli for
    res.json(schedule);
  } catch (err) {
    console.error('Błąd pobierania grafiku:', err);
    res.status(500).json({ error: 'Błąd serwera przy pobieraniu grafiku.' });
  }
});


// Endpoint do tworzenia wyjątków w grafiku (bez zmian)
app.post('/api/schedules', authenticateToken, authorizeEmployer, async (req, res) => {
    try {
        const { userId, startTime, endTime } = req.body;
        if (!userId || !startTime || !endTime) return res.status(400).json({ error: 'Wszystkie pola są wymagane.' });
        const result = await pool.query('INSERT INTO work_schedules (user_id, start_time, end_time) VALUES ($1, $2, $3) RETURNING *', [userId, startTime, endTime]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Błąd tworzenia zmiany:', err);
        res.status(500).json({ error: 'Błąd serwera podczas tworzenia zmiany.' });
    }
});

// Endpoint do ustawiania domyślnych godzin (bez zmian)
app.put('/api/users/:userId/default-schedule', authenticateToken, authorizeEmployer, async (req, res) => {
  try {
    const { userId } = req.params;
    const { defaultStartTime, defaultEndTime } = req.body;
    if (!defaultStartTime || !defaultEndTime || !/^\d{2}:\d{2}(:\d{2})?$/.test(defaultStartTime) || !/^\d{2}:\d{2}(:\d{2})?$/.test(defaultEndTime)) {
         return res.status(400).json({ error: 'Nieprawidłowy format czasu. Oczekiwano HH:MM lub HH:MM:SS.' });
    }
    const result = await pool.query(
      'UPDATE users SET default_start_time = $1, default_end_time = $2 WHERE id = $3 AND role = \'employee\' RETURNING id, full_name, default_start_time, default_end_time',
      [defaultStartTime, defaultEndTime, userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono pracownika o podanym ID.' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Błąd aktualizacji domyślnego grafiku:', err);
    res.status(500).json({ error: 'Błąd serwera.' });
  }
});

// --- Endpointy Wniosków Urlopowych (bez zmian) ---
app.post('/api/leave-requests', authenticateToken, async (req, res) => {
    const { startDate, endDate, reason } = req.body;
    try {
        const result = await pool.query('INSERT INTO leave_requests (user_id, start_date, end_date, reason) VALUES ($1, $2, $3, $4) RETURNING *', [req.user.userId, startDate, endDate, reason]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Błąd dodawania wniosku urlopowego:', err);
        res.status(500).json({ error: 'Błąd serwera.' });
    }
});

app.get('/api/leave-requests/my', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM leave_requests WHERE user_id = $1 ORDER BY start_date DESC', [req.user.userId]);
        res.json(result.rows);
    } catch (err) {
        console.error('Błąd pobierania wniosków urlopowych (my):', err);
        res.status(500).json({ error: 'Błąd serwera.' });
    }
});

app.get('/api/leave-requests/pending', authenticateToken, authorizeEmployer, async (req, res) => {
    try {
        const result = await pool.query(`SELECT lr.*, u.full_name FROM leave_requests lr JOIN users u ON lr.user_id = u.id WHERE lr.status = 'pending' ORDER BY lr.created_at ASC`);
        res.json(result.rows);
    } catch (err) {
        console.error('Błąd pobierania wniosków urlopowych (pending):', err);
        res.status(500).json({ error: 'Błąd serwera.' });
    }
});

app.put('/api/leave-requests/:id/status', authenticateToken, authorizeEmployer, async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    try {
        const result = await pool.query('UPDATE leave_requests SET status = $1 WHERE id = $2 RETURNING *', [status, id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono wniosku.' });
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Błąd aktualizacji wniosku urlopowego:', err);
        res.status(500).json({ error: 'Błąd serwera.' });
    }
});

// --- Endpointy Wniosków o Zmianę Czasu (bez zmian) ---
app.post('/api/time-change-requests', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { workDate, requestedStartTime, requestedEndTime, reason } = req.body;
    if (!workDate) return res.status(400).json({ error: 'Data jest wymagana.' });
    const result = await pool.query(
      `INSERT INTO time_change_requests (user_id, work_date, requested_start_time, requested_end_time, reason) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [userId, workDate, requestedStartTime || null, requestedEndTime || null, reason]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Błąd składania wniosku o zmianę czasu:', err);
    res.status(500).json({ error: 'Błąd serwera.' });
  }
});

app.get('/api/time-change-requests/pending', authenticateToken, authorizeEmployer, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT tcr.*, u.full_name FROM time_change_requests tcr JOIN users u ON tcr.user_id = u.id WHERE tcr.status = 'pending' ORDER BY tcr.created_at ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Błąd pobierania wniosków o zmianę czasu:', err);
    res.status(500).json({ error: 'Błąd serwera.' });
  }
});

app.put('/api/time-change-requests/:id/status', authenticateToken, authorizeEmployer, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ error: 'Nieprawidłowy status.' });
    const result = await pool.query('UPDATE time_change_requests SET status = $1 WHERE id = $2 RETURNING *', [status, id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Nie znaleziono wniosku.' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Błąd aktualizacji wniosku o zmianę czasu:', err);
    res.status(500).json({ error: 'Błąd serwera.' });
  }
});

// Endpoint salda urlopowego (bez zmian)
app.get('/api/leave-balance', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const entitlementResult = await pool.query('SELECT vacation_days_entitlement FROM users WHERE id = $1', [userId]);
    const entitlement = entitlementResult.rows[0]?.vacation_days_entitlement ?? 0;
    const approvedDaysResult = await pool.query(
      `SELECT SUM(end_date - start_date + 1) as total_approved FROM leave_requests WHERE user_id = $1 AND status = 'approved' AND EXTRACT(YEAR FROM start_date) = EXTRACT(YEAR FROM CURRENT_DATE)`, [userId]
    );
    const usedDays = parseInt(approvedDaysResult.rows[0].total_approved || 0, 10);
    res.json({ entitlement, used: usedDays, remaining: entitlement - usedDays });
  } catch (err) {
    console.error('Błąd obliczania urlopu:', err);
    res.status(500).json({ error: 'Błąd serwera przy obliczaniu urlopu.' });
  }
});

// --- Uruchomienie serwera ---
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Serwer domelHR uruchomiony na porcie ${PORT}`);
});