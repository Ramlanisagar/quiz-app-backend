const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const ExcelJS = require('exceljs');

const app = express();
app.use(cors());
app.use(express.json());

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const QUIZZES_FILE = path.join(DATA_DIR, 'quizzes.json');
const ATTEMPTS_FILE = path.join(DATA_DIR, 'attempts.json');
const JWT_SECRET = 'super-secret-jwt-key-2025';

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);

// Initialize files
if (!fs.existsSync(USERS_FILE)) {
  const initialUsers = {
    admin: {
      password: bcrypt.hashSync('admin123', 10),
      role: 'admin'
    }
  };
  fs.writeFileSync(USERS_FILE, JSON.stringify(initialUsers, null, 2));
}

if (!fs.existsSync(QUIZZES_FILE)) {
  fs.writeFileSync(QUIZZES_FILE, JSON.stringify([], null, 2));
}

if (!fs.existsSync(ATTEMPTS_FILE)) {
  fs.writeFileSync(ATTEMPTS_FILE, JSON.stringify({}, null, 2));
}

const readJSON = (file) => JSON.parse(fs.readFileSync(file));
const writeJSON = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
};

const isManager = (req, res, next) => {
  if (req.user.role !== 'manager') return res.status(403).json({ error: 'Manager only' });
  next();
};

// ================ AUTH ROUTES ================
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });

  const users = readJSON(USERS_FILE);
  if (users[username]) return res.status(400).json({ error: 'Username taken' });

  users[username] = { password: bcrypt.hashSync(password, 10), role: 'student' };
  writeJSON(USERS_FILE, users);
  res.json({ message: 'Registered' });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const users = readJSON(USERS_FILE);
  const user = users[username];
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, role: user.role, username });
});

// ================ QUIZ ROUTES ================
app.get('/api/quizzes', (req, res) => {
  const quizzes = readJSON(QUIZZES_FILE);
  const activeQuizzes = quizzes.filter(q => q.active !== false).map(q => ({ id: q.id, title: q.title }));
  res.json(activeQuizzes);
});

app.get('/api/quizzes/admin', authenticate, isAdmin, (req, res) => {
  const quizzes = readJSON(QUIZZES_FILE);
  res.json(quizzes);
});

// Manager sees only active quizzes with attempt counts
app.get('/api/quizzes/manager', authenticate, isManager, (req, res) => {
  const quizzes = readJSON(QUIZZES_FILE);
  const attempts = readJSON(ATTEMPTS_FILE);

  const activeQuizzes = quizzes.filter(q => q.active !== false).map(quiz => {
    let totalAttempts = 0;
    let uniqueStudents = 0;
    const studentsSet = new Set();

    Object.entries(attempts).forEach(([username, userAttempts]) => {
      if (userAttempts[quiz.id]) {
        const quizAttempts = Array.isArray(userAttempts[quiz.id]) 
          ? userAttempts[quiz.id] 
          : [userAttempts[quiz.id]];
        totalAttempts += quizAttempts.length;
        studentsSet.add(username);
      }
    });

    uniqueStudents = studentsSet.size;

    return {
      id: quiz.id,
      title: quiz.title,
      questionsCount: quiz.questions.length,
      totalAttempts,
      uniqueStudents
    };
  });

  res.json(activeQuizzes);
});

app.get('/api/quizzes/:id', authenticate, (req, res) => {
  const quizzes = readJSON(QUIZZES_FILE);
  const quiz = quizzes.find(q => q.id === req.params.id);
  if (!quiz) return res.status(404).json({ error: 'Not found' });
  if (req.user.role !== 'admin' && quiz.active === false) return res.status(403).json({ error: 'Inactive quiz' });
  // res.json(quiz);

  // Only shuffle for students (admin sees original order for editing)
  if (req.user.role === 'student') {
    // Create a shuffled copy of questions
    const shuffledQuestions = [...quiz.questions].sort(() => Math.random() - 0.5);
    res.json({ ...quiz, questions: shuffledQuestions });
  } else {
    // Admin sees original order
    res.json(quiz);
  }
});

app.post('/api/quizzes', authenticate, isAdmin, (req, res) => {
  const { title, questions } = req.body;
  const quizzes = readJSON(QUIZZES_FILE);
  const newQuiz = { id: Date.now().toString(), title, questions, active: true };
  quizzes.push(newQuiz);
  writeJSON(QUIZZES_FILE, quizzes);
  res.json(newQuiz);
});

app.put('/api/quizzes/:id', authenticate, isAdmin, (req, res) => {
  const { title, questions, active } = req.body;
  const quizzes = readJSON(QUIZZES_FILE);
  const index = quizzes.findIndex(q => q.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Not found' });

  if (title) quizzes[index].title = title;
  if (questions) quizzes[index].questions = questions;
  if (active !== undefined) quizzes[index].active = active;

  writeJSON(QUIZZES_FILE, quizzes);
  res.json(quizzes[index]);
});

app.delete('/api/quizzes/:id', authenticate, isAdmin, (req, res) => {
  const quizzes = readJSON(QUIZZES_FILE);
  const index = quizzes.findIndex(q => q.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: 'Not found' });

  quizzes.splice(index, 1);
  writeJSON(QUIZZES_FILE, quizzes);
  res.json({ message: 'Deleted' });
});

// ================ ATTEMPTS ROUTES ================
app.get('/api/attempts', authenticate, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ error: 'Students only' });
  const attempts = readJSON(ATTEMPTS_FILE);
  res.json(attempts[req.user.username] || {});
});

app.post('/api/attempts', authenticate, (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ error: 'Students only' });
  const { quizId, score } = req.body;
  if (!quizId || score === undefined) return res.status(400).json({ error: 'Missing fields' });

  const attempts = readJSON(ATTEMPTS_FILE);

  // Initialize user and quiz
  if (!attempts[req.user.username]) attempts[req.user.username] = {};
  if (!attempts[req.user.username][quizId]) attempts[req.user.username][quizId] = [];

  let quizAttempts = attempts[req.user.username][quizId];

  // Convert old single object to array if needed
  if (!Array.isArray(quizAttempts) && typeof quizAttempts === 'object' && quizAttempts !== null) {
    quizAttempts = [{
      score: quizAttempts.score,
      passed: quizAttempts.passed,
      timestamp: quizAttempts.timestamp || new Date().toISOString(),
      date: quizAttempts.date || new Date().toLocaleDateString(),
      time: quizAttempts.time || new Date().toLocaleTimeString(),
      attemptNumber: 1
    }];
    attempts[req.user.username][quizId] = quizAttempts; // Update in memory
  }

  // Ensure it's an array now
  if (!Array.isArray(quizAttempts)) quizAttempts = [];

  const now = new Date();
  const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  // Filter recent attempts safely
  const recentAttempts = quizAttempts.filter(attempt => {
    const attemptTime = new Date(attempt.timestamp || attempt.date); // fallback
    return attemptTime > twentyFourHoursAgo;
  });

  if (recentAttempts.length >= 3) {
    const oldestRecent = new Date(Math.min(...recentAttempts.map(a => new Date(a.timestamp || a.date))));
    const blockUntil = new Date(oldestRecent.getTime() + 24 * 60 * 60 * 1000);

    return res.status(429).json({
      error: 'Attempt limit reached',
      message: 'You have used all 3 attempts in the last 24 hours.',
      blockedUntil: blockUntil.toLocaleString()
    });
  }

  // Record new attempt
  const newAttempt = {
    score: parseFloat(score),
    passed: score >= 60,
    timestamp: now.toISOString(),
    date: now.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }),
    time: now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
    attemptNumber: quizAttempts.length + 1
  };

  quizAttempts.push(newAttempt);
  attempts[req.user.username][quizId] = quizAttempts;

  writeJSON(ATTEMPTS_FILE, attempts);

  res.json({
    message: 'Attempt recorded',
    attempt: newAttempt,
    remainingAttempts: 3 - (recentAttempts.length + 1)
  });
});

// app.post('/api/attempts', authenticate, (req, res) => {
//   if (req.user.role !== 'student') return res.status(403).json({ error: 'Students only' });
//   const { quizId, score } = req.body;
//   if (!quizId || score === undefined) return res.status(400).json({ error: 'Missing fields' });

//   const attempts = readJSON(ATTEMPTS_FILE);

//   // Initialize user if not exists
//   if (!attempts[req.user.username]) {
//     attempts[req.user.username] = {};
//   }

//   // Initialize quiz attempts as array
//   if (!attempts[req.user.username][quizId]) {
//     attempts[req.user.username][quizId] = [];
//   }

//   // If old format exists (single object), convert to array
//   if (!Array.isArray(attempts[req.user.username][quizId]) && attempts[req.user.username][quizId] !== undefined) {
//     const oldAttempt = attempts[req.user.username][quizId];
//     attempts[req.user.username][quizId] = [{
//       score: oldAttempt.score,
//       passed: oldAttempt.passed,
//       timestamp: oldAttempt.timestamp || new Date().toISOString(),
//       date: oldAttempt.date || new Date().toLocaleDateString(),
//       time: oldAttempt.time || new Date().toLocaleTimeString(),
//       attemptNumber: 1
//     }];
//   }

//   // Now safely push new attempt
//   const newAttempt = {
//     score: parseFloat(score),
//     passed: score >= 60,
//     timestamp: new Date().toISOString(),
//     date: new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }),
//     time: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
//     attemptNumber: attempts[req.user.username][quizId].length + 1
//   };

//   attempts[req.user.username][quizId].push(newAttempt);

//   writeJSON(ATTEMPTS_FILE, attempts);
//   res.json({ message: 'Attempt recorded', attempt: newAttempt });
// });

// ================ EXCEL RESULTS DOWNLOAD ================
app.get('/api/quizzes/:id/results', authenticate, (req, res, next) => {
  if (req.user.role !== 'admin' && req.user.role !== 'manager') {
    return res.status(403).json({ error: 'Admin or Manager only' });
  }
  next();
}, async (req, res) => {
  const quizId = req.params.id;
  const quizzes = readJSON(QUIZZES_FILE);
  const quiz = quizzes.find(q => q.id === req.params.id);
  if (!quiz) return res.status(404).json({ error: 'Quiz not found' });

  const attempts = readJSON(ATTEMPTS_FILE);
  const results = [];

  for (const [username, userAttempts] of Object.entries(attempts)) {
    const quizAttempts = userAttempts[quizId];

    if (!quizAttempts) continue;

    // Handle both old (object) and new (array) formats
    if (Array.isArray(quizAttempts)) {
      quizAttempts.forEach((attempt, index) => {
        results.push({
          username,
          attemptNumber: index + 1,
          score: attempt.score,
          status: attempt.passed ? 'Pass' : 'Fail',
          date: attempt.date || 'Unknown',
          time: attempt.time || ''
        });
      });
    } else if (typeof quizAttempts === 'object' && quizAttempts !== null) {
      // Old single attempt format
      results.push({
        username,
        attemptNumber: 1,
        score: quizAttempts.score,
        status: quizAttempts.passed ? 'Pass' : 'Fail',
        date: quizAttempts.date || 'Unknown',
        time: quizAttempts.time || ''
      });
    }
  }

  // Sort by date descending (newest first)
  results.sort((a, b) => {
    const dateA = a.date === 'Unknown' ? 0 : new Date(a.date);
    const dateB = b.date === 'Unknown' ? 0 : new Date(b.date);
    return dateB - dateA;
  });

  const ExcelJS = require('exceljs');
  const workbook = new ExcelJS.Workbook();
  const worksheet = workbook.addWorksheet('All Attempts');

  worksheet.columns = [
    { header: 'Student Username', key: 'username', width: 25 },
    { header: 'Attempt #', key: 'attemptNumber', width: 12 },
    { header: 'Score (%)', key: 'score', width: 15 },
    { header: 'Status', key: 'status', width: 12 },
    { header: 'Date', key: 'date', width: 20 },
    { header: 'Time', key: 'time', width: 12 }
  ];

  results.forEach(row => worksheet.addRow(row));

  // Style header
  const headerRow = worksheet.getRow(1);
  headerRow.font = { bold: true, color: { argb: 'FFFFFFFF' } };
  headerRow.fill = {
    type: 'pattern',
    pattern: 'solid',
    fgColor: { argb: 'FF232F3E' }  // Dark navy like navbar
  };
  headerRow.alignment = { vertical: 'middle', horizontal: 'center' };

  // Set response headers
  res.setHeader(
    'Content-Type',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  );
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="${quiz.title.replace(/[^a-z0-9]/gi, '_')}_All_Attempts.xlsx"`
  );

  // Write and end properly
  workbook.xlsx.write(res)
    .then(() => {
      res.end();
    })
    .catch(err => {
      console.error('Excel write error:', err);
      res.status(500).json({ error: 'Failed to generate Excel' });
    });
});

// Admin only: Get all attempts (to count per quiz)
app.get('/api/attempts/all', authenticate, isAdmin, (req, res) => {
  const attempts = readJSON(ATTEMPTS_FILE);
  res.json(attempts);
});

app.listen(5000, () => console.log('Backend running on http://localhost:5000'));