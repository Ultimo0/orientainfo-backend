const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// ========== CONNEXION POSTGRESQL ==========
const pool = new Pool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 5432,
    ssl: { rejectUnauthorized: false }
});

// Créer la table automatiquement
pool.query(`
    CREATE TABLE IF NOT EXISTS utilisateurs (
        id SERIAL PRIMARY KEY,
        nom VARCHAR(100),
        email VARCHAR(100) UNIQUE,
        mot_de_passe VARCHAR(255),
        branche_principale VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
`).then(() => {
    console.log('✅ Table créée ou déjà existante !');
}).catch(err => console.error('Erreur table:', err));

// ========== INSCRIPTION ==========
app.post('/inscription', async (req, res) => {
    const { nom, email, mot_de_passe } = req.body;

    try {
        const exist = await pool.query(
            'SELECT * FROM utilisateurs WHERE email = $1', [email]
        );

        if (exist.rows.length > 0) {
            return res.status(400).json({ message: 'Email déjà utilisé' });
        }

        const hash = await bcrypt.hash(mot_de_passe, 10);

        await pool.query(
            'INSERT INTO utilisateurs (nom, email, mot_de_passe) VALUES ($1, $2, $3)',
            [nom, email, hash]
        );

        res.status(201).json({ message: 'Compte créé avec succès !' });

    } catch (err) {
        res.status(500).json({ message: 'Erreur serveur' });
    }
});

// ========== CONNEXION ==========
app.post('/connexion', async (req, res) => {
    const { email, mot_de_passe } = req.body;

    try {
        const result = await pool.query(
            'SELECT * FROM utilisateurs WHERE email = $1', [email]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ message: 'Email ou mot de passe incorrect' });
        }

        const utilisateur = result.rows[0];
        const valide = await bcrypt.compare(mot_de_passe, utilisateur.mot_de_passe);

        if (!valide) {
            return res.status(400).json({ message: 'Email ou mot de passe incorrect' });
        }

        const token = jwt.sign(
            { id: utilisateur.id, nom: utilisateur.nom },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Connexion réussie !',
            token,
            utilisateur: {
                id: utilisateur.id,
                nom: utilisateur.nom,
                email: utilisateur.email
            }
        });

    } catch (err) {
        res.status(500).json({ message: 'Erreur serveur' });
    }
});

// ========== SAUVEGARDER RÉSULTAT ==========
app.post('/sauvegarder-resultat', async (req, res) => {
    const { token, branche_principale } = req.body;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        await pool.query(
            'UPDATE utilisateurs SET branche_principale = $1 WHERE id = $2',
            [branche_principale, decoded.id]
        );

        res.json({ message: 'Résultat sauvegardé !' });

    } catch (err) {
        res.status(401).json({ message: 'Token invalide' });
    }
});

// ========== STATISTIQUES ==========
app.get('/stats', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT branche_principale, COUNT(*) as total FROM utilisateurs WHERE branche_principale IS NOT NULL GROUP BY branche_principale ORDER BY total DESC'
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ message: 'Erreur serveur' });
    }
});

// ========== EMPÊCHER LE SERVEUR DE S'ENDORMIR ==========
setInterval(() => {
    fetch('https://ultimo0.github.io/orientainfo')
        .catch(() => {});
}, 14 * 60 * 1000);

// ========== DÉMARRER ==========
app.listen(process.env.PORT || 3000, () => {
    console.log('🚀 Serveur démarré !');
});
