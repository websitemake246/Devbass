const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'your-super-secret-key-change-this-in-production';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Ensure uploads directory exists
if (!fs.existsSync('./uploads')) {
    fs.mkdirSync('./uploads');
}

// Database setup
const db = new sqlite3.Database('./baas.db');

// File storage setup
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userDir = `./uploads/${req.userId}`;
        if (!fs.existsSync(userDir)) {
            fs.mkdirSync(userDir, { recursive: true });
        }
        cb(null, userDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + '-' + file.originalname;
        cb(null, uniqueName);
    }
});

const upload = multer({ 
    storage: storage, 
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// Initialize database tables
db.serialize(() => {
    // Users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Collections table
    db.run(`
        CREATE TABLE IF NOT EXISTS collections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, name)
        )
    `);
    
    // Records table
    db.run(`
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            collection_id INTEGER NOT NULL,
            data TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(collection_id) REFERENCES collections(id) ON DELETE CASCADE
        )
    `);
    
    // Files table
    db.run(`
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            size INTEGER NOT NULL,
            mime_type TEXT NOT NULL,
            file_path TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);
});

// Authentication middleware
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const apiKey = req.headers['x-api-key'];
    
    // Try JWT token first
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            req.userId = decoded.userId;
            return next();
        } catch (err) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }
    }
    
    // Try API key
    if (apiKey) {
        db.get('SELECT id FROM users WHERE api_key = ?', [apiKey], (err, user) => {
            if (err || !user) {
                return res.status(401).json({ error: 'Invalid API key' });
            }
            req.userId = user.id;
            next();
        });
    } else {
        res.status(401).json({ error: 'Authentication required. Use Bearer token or X-API-Key header' });
    }
};

// ============= AUTH ROUTES =============

// Register
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    try {
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Generate API key
        const apiKey = 'dev_' + crypto.randomBytes(32).toString('hex');
        
        // Insert user
        db.run(
            'INSERT INTO users (email, password, api_key) VALUES (?, ?, ?)',
            [email, hashedPassword, apiKey],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(400).json({ error: 'Email already exists' });
                    }
                    return res.status(500).json({ error: 'Registration failed' });
                }
                
                // Generate JWT token
                const token = jwt.sign({ userId: this.lastID }, JWT_SECRET, { expiresIn: '30d' });
                
                res.json({
                    success: true,
                    token: token,
                    apiKey: apiKey,
                    userId: this.lastID,
                    email: email
                });
            }
        );
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// Login
app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            console.error('Login error:', err);
            return res.status(500).json({ error: 'Server error' });
        }
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        // Verify password
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        // Generate new token
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
        
        res.json({
            success: true,
            token: token,
            apiKey: user.api_key,
            userId: user.id,
            email: user.email
        });
    });
});

// Get current user info (including API key)
app.get('/api/user/info', authenticate, (req, res) => {
    db.get('SELECT id, email, api_key, created_at FROM users WHERE id = ?', [req.userId], (err, user) => {
        if (err || !user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({
            id: user.id,
            email: user.email,
            apiKey: user.api_key,
            createdAt: user.created_at
        });
    });
});

// ============= COLLECTION ROUTES =============

// Get all collections
app.get('/api/collections', authenticate, (req, res) => {
    db.all('SELECT * FROM collections WHERE user_id = ? ORDER BY created_at DESC', [req.userId], (err, collections) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch collections' });
        }
        res.json(collections);
    });
});

// Create collection
app.post('/api/collections', authenticate, (req, res) => {
    const { name } = req.body;
    
    if (!name || name.trim() === '') {
        return res.status(400).json({ error: 'Collection name is required' });
    }
    
    db.run(
        'INSERT INTO collections (user_id, name) VALUES (?, ?)',
        [req.userId, name.trim()],
        function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ error: 'Collection with this name already exists' });
                }
                return res.status(500).json({ error: 'Failed to create collection' });
            }
            res.json({ 
                id: this.lastID, 
                name: name.trim(),
                user_id: req.userId,
                created_at: new Date().toISOString()
            });
        }
    );
});

// Delete collection
app.delete('/api/collections/:collectionId', authenticate, (req, res) => {
    const { collectionId } = req.params;
    
    db.run(
        'DELETE FROM collections WHERE id = ? AND user_id = ?',
        [collectionId, req.userId],
        function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to delete collection' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Collection not found' });
            }
            res.json({ success: true, message: 'Collection deleted' });
        }
    );
});

// ============= RECORD ROUTES =============

// Get all records in a collection
app.get('/api/collections/:collectionId/records', authenticate, (req, res) => {
    const { collectionId } = req.params;
    
    // Verify collection belongs to user
    db.get('SELECT id FROM collections WHERE id = ? AND user_id = ?', [collectionId, req.userId], (err, collection) => {
        if (err || !collection) {
            return res.status(404).json({ error: 'Collection not found' });
        }
        
        db.all('SELECT * FROM records WHERE collection_id = ? ORDER BY created_at DESC', [collectionId], (err, records) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch records' });
            }
            
            // Parse JSON data for each record
            const parsedRecords = records.map(record => {
                try {
                    return {
                        id: record.id,
                        data: JSON.parse(record.data),
                        created_at: record.created_at,
                        updated_at: record.updated_at
                    };
                } catch (e) {
                    return {
                        id: record.id,
                        data: record.data,
                        created_at: record.created_at,
                        updated_at: record.updated_at
                    };
                }
            });
            
            res.json(parsedRecords);
        });
    });
});

// Create record
app.post('/api/collections/:collectionId/records', authenticate, (req, res) => {
    const { collectionId } = req.params;
    const data = req.body;
    
    // Verify collection belongs to user
    db.get('SELECT id FROM collections WHERE id = ? AND user_id = ?', [collectionId, req.userId], (err, collection) => {
        if (err || !collection) {
            return res.status(404).json({ error: 'Collection not found' });
        }
        
        const dataString = JSON.stringify(data);
        db.run(
            'INSERT INTO records (collection_id, data) VALUES (?, ?)',
            [collectionId, dataString],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Failed to create record' });
                }
                res.json({ 
                    id: this.lastID, 
                    data: data,
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                });
            }
        );
    });
});

// Update record
app.put('/api/records/:recordId', authenticate, (req, res) => {
    const { recordId } = req.params;
    const data = req.body;
    
    // Verify record belongs to user through collection
    db.get(`
        SELECT records.id FROM records 
        JOIN collections ON collections.id = records.collection_id 
        WHERE records.id = ? AND collections.user_id = ?
    `, [recordId, req.userId], (err, record) => {
        if (err || !record) {
            return res.status(404).json({ error: 'Record not found' });
        }
        
        const dataString = JSON.stringify(data);
        db.run(
            'UPDATE records SET data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [dataString, recordId],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Failed to update record' });
                }
                res.json({ success: true, message: 'Record updated' });
            }
        );
    });
});

// Delete record
app.delete('/api/records/:recordId', authenticate, (req, res) => {
    const { recordId } = req.params;
    
    db.get(`
        SELECT records.id FROM records 
        JOIN collections ON collections.id = records.collection_id 
        WHERE records.id = ? AND collections.user_id = ?
    `, [recordId, req.userId], (err, record) => {
        if (err || !record) {
            return res.status(404).json({ error: 'Record not found' });
        }
        
        db.run('DELETE FROM records WHERE id = ?', [recordId], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to delete record' });
            }
            res.json({ success: true, message: 'Record deleted' });
        });
    });
});

// ============= FILE ROUTES =============

// Upload file
app.post('/api/files/upload', authenticate, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const file = req.file;
    db.run(
        `INSERT INTO files (user_id, filename, original_name, size, mime_type, file_path) 
         VALUES (?, ?, ?, ?, ?, ?)`,
        [req.userId, file.filename, file.originalname, file.size, file.mimetype, file.path],
        function(err) {
            if (err) {
                // Clean up file if DB insert fails
                fs.unlink(file.path, () => {});
                return res.status(500).json({ error: 'Failed to save file info' });
            }
            
            res.json({
                id: this.lastID,
                filename: file.filename,
                original_name: file.originalname,
                size: file.size,
                mime_type: file.mimetype,
                url: `/api/files/${file.filename}`,
                created_at: new Date().toISOString()
            });
        }
    );
});

// Get all files
app.get('/api/files', authenticate, (req, res) => {
    db.all(
        'SELECT id, original_name, size, mime_type, created_at, filename FROM files WHERE user_id = ? ORDER BY created_at DESC',
        [req.userId],
        (err, files) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to fetch files' });
            }
            res.json(files);
        }
    );
});

// Download file
app.get('/api/files/:filename', authenticate, (req, res) => {
    const { filename } = req.params;
    
    db.get(
        'SELECT file_path, original_name, mime_type FROM files WHERE filename = ? AND user_id = ?',
        [filename, req.userId],
        (err, file) => {
            if (err || !file) {
                return res.status(404).json({ error: 'File not found' });
            }
            
            if (fs.existsSync(file.file_path)) {
                res.setHeader('Content-Disposition', `attachment; filename="${file.original_name}"`);
                res.setHeader('Content-Type', file.mime_type);
                res.sendFile(path.resolve(file.file_path));
            } else {
                res.status(404).json({ error: 'File not found on server' });
            }
        }
    );
});

// Delete file
app.delete('/api/files/:fileId', authenticate, (req, res) => {
    const { fileId } = req.params;
    
    db.get('SELECT file_path FROM files WHERE id = ? AND user_id = ?', [fileId, req.userId], (err, file) => {
        if (err || !file) {
            return res.status(404).json({ error: 'File not found' });
        }
        
        // Delete physical file
        if (fs.existsSync(file.file_path)) {
            fs.unlink(file.file_path, () => {});
        }
        
        // Delete database record
        db.run('DELETE FROM files WHERE id = ?', [fileId], function(err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to delete file record' });
            }
            res.json({ success: true, message: 'File deleted' });
        });
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`\n✅ BaaS Server is running!`);
    console.log(`📍 URL: http://localhost:${PORT}`);
    console.log(`📡 API Base: http://localhost:${PORT}/api\n`);
    console.log('Available endpoints:');
    console.log('  POST   /api/auth/register  - Create account');
    console.log('  POST   /api/auth/login     - Login');
    console.log('  GET    /api/collections    - List collections');
    console.log('  POST   /api/collections    - Create collection');
    console.log('  GET    /api/collections/:id/records - Get records');
    console.log('  POST   /api/collections/:id/records - Create record');
    console.log('  PUT    /api/records/:id    - Update record');
    console.log('  DELETE /api/records/:id    - Delete record');
    console.log('  POST   /api/files/upload   - Upload file');
    console.log('  GET    /api/files          - List files');
    console.log('  DELETE /api/files/:id      - Delete file\n');
});
