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
  if (!attempts[req.user.username]) attempts[req.user.username] = {};

  attempts[req.user.username][quizId] = {
    score: parseFloat(score),
    passed: score >= 60,
    date: new Date().toISOString().split('T')[0]
  };

  writeJSON(ATTEMPTS_FILE, attempts);
  res.json({ message: 'Submitted', score });
});

// ================ EXCEL RESULTS DOWNLOAD ================
app.get('/api/quizzes/:id/results', authenticate, isAdmin, async (req, res) => {
  const quizId = req.params.id;
  const quizzes = readJSON(QUIZZES_FILE);
  const quiz = quizzes.find(q => q.id === quizId);
  if (!quiz) return res.status(404).json({ error: 'Quiz not found' });

  const attempts = readJSON(ATTEMPTS_FILE);
  const results = [];

  for (const [username, userAttempts] of Object.entries(attempts)) {
    if (userAttempts[quizId]) {
      const attempt = userAttempts[quizId];
      results.push({
        username,
        score: attempt.score,
        status: attempt.passed ? 'Pass' : 'Fail',
        date: attempt.date
      });
    }
  }

  const workbook = new ExcelJS.Workbook();
  const worksheet = workbook.addWorksheet('Results');

  worksheet.columns = [
    { header: 'Student Username', key: 'username', width: 25 },
    { header: 'Score (%)', key: 'score', width: 15 },
    { header: 'Status', key: 'status', width: 12 },
    { header: 'Date Taken', key: 'date', width: 15 }
  ];

  results.forEach(row => worksheet.addRow(row));

  worksheet.getRow(1).font = { bold: true, color: { argb: 'FFFFFFFF' } };
  worksheet.getRow(1).fill = {
    type: 'pattern',
    pattern: 'solid',
    fgColor: { argb: 'FF4472C4' }
  };

  res.setHeader(
    'Content-Type',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  );
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="${quiz.title.replace(/[^a-z0-9]/gi, '_')}_Results.xlsx"`
  );

  await workbook.xlsx.write(res);
  res.end();
});

// Admin only: Get all attempts (to count per quiz)
app.get('/api/attempts/all', authenticate, isAdmin, (req, res) => {
  const attempts = readJSON(ATTEMPTS_FILE);
  res.json(attempts);
});

app.listen(5000, () => console.log('Backend running on http://localhost:5000'));