const express = require('express');
const fs = require('fs');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

const LOG_FILE = './logs.json';

function loadLogs() {
  try {
    const data = fs.readFileSync(LOG_FILE, 'utf8');
    return JSON.parse(data);
  } catch { return []; }
}

function saveLogs(logs) {
  fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));
}

app.get('/api/logs', (req, res) => {
  res.json(loadLogs());
});

app.post('/api/logs', (req, res) => {
  const entry = req.body;
  if (!entry.ip || !entry.time) {
    return res.status(400).json({ error: 'Invalid data' });
  }
  const logs = loadLogs();
  logs.push(entry);
  saveLogs(logs);
  res.json({ success: true });
});

app.delete('/api/logs', (req, res) => {
  saveLogs([]);
  res.json({ success: true });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));