const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your-super-secret-key-change-this';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Database setup
const db = new sqlite3.Database('./baas.db');

// File storage setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userDir = `./uploads/${req.userId}`;
        if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
        cb(null, userDir);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB limit

// Initialize database
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            api_key TEXT UNIQUE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS collections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            collection_id INTEGER,
            data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(collection_id) REFERENCES collections(id)
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            original_name TEXT,
            size INTEGER,
            mime_type TEXT,
            file_path TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    `);
});

// Authentication middleware
const authenticate = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    const apiKey = req.headers['x-api-key'];
    
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            req.userId = decoded.userId;
            return next();
        } catch (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }
    }
    
    if (apiKey) {
        db.get('SELECT id FROM users WHERE api_key = ?', [apiKey], (err, user) => {
            if (err || !user) return res.status(401).json({ error: 'Invalid API key' });
            req.userId = user.id;
            next();
        });
    } else {
        res.status(401).json({ error: 'Authentication required' });
    }
};

// Routes
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const apiKey = require('crypto').randomBytes(32).toString('hex');
    
    db.run('INSERT INTO users (email, password, api_key) VALUES (?, ?, ?)',
        [email, hashedPassword, apiKey],
        function(err) {
            if (err) return res.status(400).json({ error: 'Email already exists' });
            const token = jwt.sign({ userId: this.lastID }, JWT_SECRET);
            res.json({ token, apiKey, userId: this.lastID });
        }
    );
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
        
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
        
        const token = jwt.sign({ userId: user.id }, JWT_SECRET);
        res.json({ token, apiKey: user.api_key, userId: user.id });
    });
});

// Collections API
app.post('/api/collections', authenticate, (req, res) => {
    const { name } = req.body;
    db.run('INSERT INTO collections (user_id, name) VALUES (?, ?)',
        [req.userId, name],
        function(err) {
            if (err) return res.status(400).json({ error: 'Collection name already exists' });
            res.json({ id: this.lastID, name });
        }
    );
});

app.get('/api/collections', authenticate, (req, res) => {
    db.all('SELECT * FROM collections WHERE user_id = ?', [req.userId], (err, collections) => {
        res.json(collections);
    });
});

// Records API
app.post('/api/collections/:collectionId/records', authenticate, (req, res) => {
    const { collectionId } = req.params;
    const data = JSON.stringify(req.body);
    
    db.run('INSERT INTO records (collection_id, data) VALUES (?, ?)',
        [collectionId, data],
        function(err) {
            if (err) return res.status(400).json({ error: 'Failed to create record' });
            res.json({ id: this.lastID, data: req.body });
        }
    );
});

app.get('/api/collections/:collectionId/records', authenticate, (req, res) => {
    db.all('SELECT * FROM records WHERE collection_id = ?', [req.params.collectionId], (err, records) => {
        const parsedRecords = records.map(r => ({
            id: r.id,
            data: JSON.parse(r.data),
            created_at: r.created_at,
            updated_at: r.updated_at
        }));
        res.json(parsedRecords);
    });
});

app.put('/api/records/:recordId', authenticate, (req, res) => {
    const data = JSON.stringify(req.body);
    db.run('UPDATE records SET data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [data, req.params.recordId],
        function(err) {
            if (err) return res.status(400).json({ error: 'Failed to update' });
            res.json({ message: 'Updated successfully' });
        }
    );
});

app.delete('/api/records/:recordId', authenticate, (req, res) => {
    db.run('DELETE FROM records WHERE id = ?', [req.params.recordId], function(err) {
        if (err) return res.status(400).json({ error: 'Failed to delete' });
        res.json({ message: 'Deleted successfully' });
    });
});

// File upload API
app.post('/api/files/upload', authenticate, upload.single('file'), (req, res) => {
    const file = req.file;
    db.run(`INSERT INTO files (user_id, filename, original_name, size, mime_type, file_path)
            VALUES (?, ?, ?, ?, ?, ?)`,
        [req.userId, file.filename, file.originalname, file.size, file.mimetype, file.path],
        function(err) {
            if (err) return res.status(400).json({ error: 'Failed to save file info' });
            res.json({
                id: this.lastID,
                filename: file.filename,
                original_name: file.originalname,
                size: file.size,
                url: `/api/files/${file.filename}`
            });
        }
    );
});

app.get('/api/files', authenticate, (req, res) => {
    db.all('SELECT id, original_name, size, mime_type, created_at FROM files WHERE user_id = ?',
        [req.userId], (err, files) => {
            res.json(files);
        }
    );
});

app.get('/api/files/:filename', authenticate, (req, res) => {
    const filePath = path.join(__dirname, 'uploads', req.userId.toString(), req.params.filename);
    if (fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else {
        res.status(404).json({ error: 'File not found' });
    }
});

app.delete('/api/files/:fileId', authenticate, (req, res) => {
    db.get('SELECT file_path FROM files WHERE id = ? AND user_id = ?', 
        [req.params.fileId, req.userId], (err, file) => {
            if (err || !file) return res.status(404).json({ error: 'File not found' });
            fs.unlink(file.file_path, () => {});
            db.run('DELETE FROM files WHERE id = ?', [req.params.fileId]);
            res.json({ message: 'File deleted successfully' });
        }
    );
});

app.listen(PORT, () => {
    console.log(`🚀 BaaS Server running on http://localhost:${PORT}`);
    console.log(`📁 API Base URL: http://localhost:${PORT}/api`);
});
