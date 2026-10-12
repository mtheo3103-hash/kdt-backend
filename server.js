const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

const mongoUri = process.env.MONGO_URI;
if (!mongoUri) console.error('❌ FEHLER: MONGO_URI fehlt!');

mongoose.connect(mongoUri)
    .then(() => console.log('✅ MongoDB verbunden'))
    .catch(err => console.error('❌ MongoDB Fehler:', err));

// --- SCHEMAS ---
const UserSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true }, // Eindeutige Nutzer-ID (z.B. Timestamp-basiert oder random String)
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    githubToken: { type: String, default: '' },
    githubRepo: { type: String, default: 'mtheo3103-hash/KDT' }
});
const User = mongoose.model('User', UserSchema);

// Projekt-Schema: Ordnet das Projekt eindeutig der userId zu
const ProjectSchema = new mongoose.Schema({
    userId: { type: String, required: true }, // Die ID des Nutzers (z.B. "171829384")
    name: { type: String, required: true },
    type: { type: String, enum: ['addon', 'repo'], required: true },
    data: { type: Object, required: true },
    updatedAt: { type: Date, default: Date.now }
});
const Project = mongoose.model('Project', ProjectSchema);

// Middleware zur Authentifizierung
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Kein Token' });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (err) {
        res.status(403).json({ error: 'Ungültiger Token' });
    }
};

// --- AUTH ROUTES ---
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Generiere eine eindeutige numerische oder alphanumerische Nutzer-ID (z.B. 9-stelliger Zufallscode)
        const customUserId = Math.floor(100000000 + Math.random() * 900000000).toString();

        const newUser = new User({
            userId: customUserId,
            username,
            password: hashedPassword
        });

        await newUser.save();
        res.json({ message: 'Registrierung erfolgreich!', userId: customUserId });
    } catch (err) {
        res.status(400).json({ error: 'Benutzername existiert bereits oder ungültig.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: 'Ungültige Anmeldedaten' });
        }
        
        const token = jwt.sign({ id: user._id, userId: user.userId, username: user.username }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, username: user.username, userId: user.userId, githubRepo: user.githubRepo });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/settings', verifyToken, async (req, res) => {
    try {
        const { githubToken, githubRepo } = req.body;
        await User.findByIdAndUpdate(req.user.id, { githubToken, githubRepo });
        res.json({ message: 'Einstellungen gespeichert!' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- PROJECT ROUTES (Nutzer-getrennter Bereich) ---
app.get('/api/projects', verifyToken, async (req, res) => {
    try {
        // Holt nur die Projekte, die exakt zu dieser userId gehören
        const projects = await Project.find({ userId: req.user.userId });
        res.json(projects);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/projects', verifyToken, async (req, res) => {
    try {
        const { name, type, data } = req.body;
        // Speichert das Projekt im Bereich des Nutzers (userId/projects)
        const project = await Project.findOneAndUpdate(
            { userId: req.user.userId, name, type },
            { data, updatedAt: Date.now() },
            { upsert: true, new: true }
        );
        res.json({ message: `Projekt in ${req.user.userId}/projects/ gespeichert!`, project });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- GITHUB PUBLISH ROUTE ---
app.post('/api/publish-github', verifyToken, async (req, res) => {
    try {
        const { files } = req.body;
        const user = await User.findById(req.user.id);
        if (!user.githubToken || !user.githubRepo) {
            return res.status(400).json({ error: 'GitHub Token in den Einstellungen fehlt!' });
        }

        const [owner, repo] = user.githubRepo.split('/');
        const headers = { Authorization: `token ${user.githubToken}`, Accept: 'application/vnd.github.v3+json' };

        for (const file of files) {
            let sha;
            try {
                const existing = await axios.get(`https://api.github.com/repos/${owner}/${repo}/contents/${file.path}`, { headers });
                sha = existing.data.sha;
            } catch (e) {}

            await axios.put(`https://api.github.com/repos/${owner}/${repo}/contents/${file.path}`, {
                message: `KDT Auto-Publish [User: ${user.userId}]: ${file.path}`,
                content: Buffer.from(file.content).toString('base64'),
                sha: sha
            }, { headers });
        }

        res.json({ message: `Erfolgreich auf GitHub gepusht (${user.githubRepo})!` });
    } catch (err) {
        res.status(500).json({ error: 'GitHub Fehler: ' + (err.response?.data?.message || err.message) });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 KDT Server läuft auf Port ${PORT}`);
});
