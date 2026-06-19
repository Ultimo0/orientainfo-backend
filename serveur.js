const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// ========== CONNEXION MYSQL ==========
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) {
        console.error('Erreur MySQL:', err);
    } else {
        console.log('✅ Connecté à MySQL !');
    }
});

// ========== INSCRIPTION ==========
app.post('/inscription', async (req, res) => {
    const { nom, email, mot_de_passe } = req.body;

    // Vérifier si l'email existe déjà
    db.query('SELECT * FROM utilisateurs WHERE email = ?', [email], async (err, results) => {
        if (results.length > 0) {
            return res.status(400).json({ message: 'Email déjà utilisé' });
        }

        // Chiffrer le mot de passe
        const hash = await bcrypt.hash(mot_de_passe, 10);

        // Insérer l'utilisateur
        db.query(
            'INSERT INTO utilisateurs (nom, email, mot_de_passe) VALUES (?, ?, ?)',
            [nom, email, hash],
            (err, result) => {
                if (err) return res.status(500).json({ message: 'Erreur serveur' });
                res.status(201).json({ message: 'Compte créé avec succès !' });
            }
        );
    });
});

// ========== CONNEXION ==========
app.post('/connexion', async (req, res) => {
    const { email, mot_de_passe } = req.body;

    db.query('SELECT * FROM utilisateurs WHERE email = ?', [email], async (err, results) => {
        if (results.length === 0) {
            return res.status(400).json({ message: 'Email ou mot de passe incorrect' });
        }

        const utilisateur = results[0];
        const valide = await bcrypt.compare(mot_de_passe, utilisateur.mot_de_passe);

        if (!valide) {
            return res.status(400).json({ message: 'Email ou mot de passe incorrect' });
        }

        // Créer le token JWT
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
    });
});

// ========== SAUVEGARDER RÉSULTAT ==========
app.post('/sauvegarder-resultat', (req, res) => {
    const { token, branche_principale } = req.body;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        db.query(
            'UPDATE utilisateurs SET branche_principale = ? WHERE id = ?',
            [branche_principale, decoded.id],
            (err) => {
                if (err) return res.status(500).json({ message: 'Erreur serveur' });
                res.json({ message: 'Résultat sauvegardé !' });
            }
        );
    } catch (err) {
        res.status(401).json({ message: 'Token invalide' });
    }
});

// ========== STATISTIQUES ==========
app.get('/stats', (req, res) => {
    db.query(
        'SELECT branche_principale, COUNT(*) as total FROM utilisateurs WHERE branche_principale IS NOT NULL GROUP BY branche_principale ORDER BY total DESC',
        (err, results) => {
            if (err) return res.status(500).json({ message: 'Erreur serveur' });
            res.json(results);
        }
    );
});

// ========== DÉMARRER ==========
app.listen(process.env.PORT, () => {
    console.log(`🚀 Serveur démarré sur http://localhost:${process.env.PORT}`);
});