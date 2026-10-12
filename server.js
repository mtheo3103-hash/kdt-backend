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

// MongoDB Verbindung mit Fehler-Abfangung
const mongoUri = process.env.MONGO_URI;
if (!mongoUri) {
    console.error('❌ FEHLER: MONGO_URI ist nicht definiert!');
}

mongoose.connect(mongoUri)
    .then(() => console.log('✅ MongoDB erfolgreich verbunden'))
    .catch(err => console.error('❌ MongoDB Verbindungsfehler:', err));

// Schemas
const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    githubToken: { type: String, default: '' },
    githubRepo: { type: String, default: 'mtheo3103-hash/KDT' }
});
const User = mongoose.model('User', UserSchema);

const ProjectSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true },
    type: { type: String, enum: ['addon', 'repo'], required: true },
    data: { type: Object, required: true },
    updatedAt: { type: Date, default: Date.now }
});
const Project = mongoose.model('Project', ProjectSchema);

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
        await new User({ username, password: hashedPassword }).save();
        res.json({ message: 'Registrierung erfolgreich!' });
    } catch (err) {
        res.status(400).json({ error: 'Benutzername existiert bereits.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({ error: 'Ungültige Anmeldedaten' });
        }
        const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, username: user.username, githubRepo: user.githubRepo });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/settings', verifyToken, async (req, res) => {
    try {
        const { githubToken, githubRepo } = req.body;
        await User.findByIdAndUpdate(req.user.id, { githubToken, githubRepo });
        res.json({ message: 'Gespeichert!' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/projects', verifyToken, async (req, res) => {
    try {
        const projects = await Project.find({ userId: req.user.id });
        res.json(projects);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/projects', verifyToken, async (req, res) => {
    try {
        const { name, type, data } = req.body;
        const project = await Project.findOneAndUpdate(
            { userId: req.user.id, name, type },
            { data, updatedAt: Date.now() },
            { upsert: true, new: true }
        );
        res.json({ message: 'Entwurf in MongoDB gespeichert!', project });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

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
                message: `KDT Auto-Publish: ${file.path}`,
                content: Buffer.from(file.content).toString('base64'),
                sha: sha
            }, { headers });
        }

        res.json({ message: `Erfolgreich auf GitHub gepusht (${user.githubRepo})!` });
    } catch (err) {
        res.status(500).json({ error: 'GitHub Fehler: ' + (err.response?.data?.message || err.message) });
    }
});

// WICHTIG FÜR RENDER: Nutze process.env.PORT und lausche global
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 KDT Server läuft erfolgreich auf Port ${PORT}`);
});
