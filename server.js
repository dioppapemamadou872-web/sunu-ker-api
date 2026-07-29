import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { rateLimit } from 'express-rate-limit';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const dossierUploads = path.join(__dirname, 'uploads');
if (!fs.existsSync(dossierUploads)) {
  fs.mkdirSync(dossierUploads, { recursive: true });
}

const adapter = new JSONFile('db.json');
const db = new Low(adapter, { logements: [], demandes: [], utilisateurs: [] });
await db.read();
db.data.utilisateurs ||= [];
db.data.utilisateurs.forEach((u) => { u.favoris ||= []; });

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(dossierUploads));

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// --- UPLOAD PHOTOS ---

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, dossierUploads),
  filename: (req, file, cb) => {
    const nomUnique = `${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(file.originalname)}`;
    cb(null, nomUnique);
  },
});

const uploadFiltre = (req, file, cb) => {
  if (file.mimetype.startsWith('image/') || file.mimetype === 'application/pdf') cb(null, true);
  else cb(new Error('Format de fichier non accepté'));
};

const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: uploadFiltre });

const uploadAnnonce = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: uploadFiltre,
}).fields([
  { name: 'photos', maxCount: 8 },
  { name: 'pieceIdentiteRecto', maxCount: 1 },
  { name: 'pieceIdentiteVerso', maxCount: 1 },
  { name: 'justificatifPropriete', maxCount: 1 },
]);

// --- PROTECTION CONTRE LES TENTATIVES EN BOUCLE ---

const limiteurConnexion = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { erreur: 'Trop de tentatives, réessayez dans 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
});

// --- AUTHENTIFICATION PAR TOKEN (JWT) ---

function verifierAdmin(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ erreur: 'Accès refusé, connexion admin requise' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'admin') throw new Error();
    next();
  } catch {
    return res.status(401).json({ erreur: 'Session expirée, reconnectez-vous' });
  }
}

function verifierProprietaire(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ erreur: 'Connexion propriétaire requise' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'proprietaire') throw new Error();
    req.proprietaireId = payload.proprietaireId;
    next();
  } catch {
    return res.status(401).json({ erreur: 'Session expirée, reconnectez-vous' });
  }
}

// --- AUTH ADMIN ---

app.post('/api/login', limiteurConnexion, (req, res) => {
  const { motDePasse } = req.body;

  if (motDePasse === ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token });
  }

  res.status(401).json({ erreur: 'Mot de passe incorrect' });
});

// --- AUTH PROPRIETAIRES ---

app.post('/api/proprietaires/inscription', limiteurConnexion, async (req, res) => {
  const { prenom, nom, telephone, motDePasse } = req.body;

  if (!prenom || !nom || !telephone || !motDePasse) {
    return res.status(400).json({ erreur: 'Tous les champs sont requis' });
  }

  if (motDePasse.length < 8) {
    return res.status(400).json({ erreur: 'Le mot de passe doit contenir au moins 8 caractères' });
  }

  if (!/^\d{9}$/.test(telephone)) {
    return res.status(400).json({ erreur: 'Le numéro de téléphone doit contenir exactement 9 chiffres' });
  }

  const existant = db.data.utilisateurs.find((u) => u.telephone === telephone);
  if (existant) {
    return res.status(409).json({ erreur: 'Un compte existe déjà avec ce numéro' });
  }

  const motDePasseHash = await bcrypt.hash(motDePasse, 10);
  const nouvelUtilisateur = {
    id: Date.now(),
    prenom,
    nom,
    telephone,
    email: null,
    photoProfil: null,
    motDePasseHash,
    favoris: [],
  };
  db.data.utilisateurs.push(nouvelUtilisateur);
  await db.write();

  const token = jwt.sign({ role: 'proprietaire', proprietaireId: nouvelUtilisateur.id }, JWT_SECRET, { expiresIn: '30d' });
  res.status(201).json({ token, prenom: nouvelUtilisateur.prenom, nom: nouvelUtilisateur.nom });
});

app.post('/api/proprietaires/connexion', limiteurConnexion, async (req, res) => {
  const { telephone, motDePasse } = req.body;
  const utilisateur = db.data.utilisateurs.find((u) => u.telephone === telephone);

  if (!utilisateur) {
    return res.status(401).json({ erreur: 'Numéro ou mot de passe incorrect' });
  }

  const motDePasseValide = await bcrypt.compare(motDePasse, utilisateur.motDePasseHash);
  if (!motDePasseValide) {
    return res.status(401).json({ erreur: 'Numéro ou mot de passe incorrect' });
  }

  const token = jwt.sign({ role: 'proprietaire', proprietaireId: utilisateur.id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, prenom: utilisateur.prenom, nom: utilisateur.nom });
});

app.get('/api/proprietaires/moi', verifierProprietaire, (req, res) => {
  const utilisateur = db.data.utilisateurs.find((u) => u.id === req.proprietaireId);
  if (!utilisateur) return res.status(404).json({ erreur: 'Utilisateur introuvable' });

  res.json({
    prenom: utilisateur.prenom,
    nom: utilisateur.nom,
    telephone: utilisateur.telephone,
    email: utilisateur.email,
    photoProfil: utilisateur.photoProfil,
  });
});

app.patch('/api/proprietaires/moi', verifierProprietaire, async (req, res) => {
  const utilisateur = db.data.utilisateurs.find((u) => u.id === req.proprietaireId);
  if (!utilisateur) return res.status(404).json({ erreur: 'Utilisateur introuvable' });

  const { prenom, nom, email, telephone } = req.body;

  if (prenom !== undefined) {
    if (prenom.trim().length < 2) return res.status(400).json({ erreur: 'Prénom invalide' });
    utilisateur.prenom = prenom.trim();
  }

  if (nom !== undefined) {
    if (nom.trim().length < 2) return res.status(400).json({ erreur: 'Nom invalide' });
    utilisateur.nom = nom.trim();
  }

  if (email !== undefined) {
    if (email && !/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({ erreur: 'Adresse email invalide' });
    }
    utilisateur.email = email || null;
  }

  if (telephone !== undefined) {
    if (!/^\d{9}$/.test(telephone)) {
      return res.status(400).json({ erreur: 'Le numéro de téléphone doit contenir exactement 9 chiffres' });
    }
    const dejaUtilise = db.data.utilisateurs.find((u) => u.telephone === telephone && u.id !== utilisateur.id);
    if (dejaUtilise) {
      return res.status(409).json({ erreur: 'Ce numéro est déjà utilisé par un autre compte' });
    }
    utilisateur.telephone = telephone;
  }

  await db.write();
  res.json({
    prenom: utilisateur.prenom,
    nom: utilisateur.nom,
    telephone: utilisateur.telephone,
    email: utilisateur.email,
    photoProfil: utilisateur.photoProfil,
  });
});

app.post('/api/proprietaires/photo', verifierProprietaire, upload.single('photo'), async (req, res) => {
  const utilisateur = db.data.utilisateurs.find((u) => u.id === req.proprietaireId);
  if (!utilisateur) return res.status(404).json({ erreur: 'Utilisateur introuvable' });
  if (!req.file) return res.status(400).json({ erreur: 'Aucune photo reçue' });

  utilisateur.photoProfil = `/uploads/${req.file.filename}`;
  await db.write();
  res.json({ photoProfil: utilisateur.photoProfil });
});

app.post('/api/proprietaires/changer-mot-de-passe', verifierProprietaire, async (req, res) => {
  const utilisateur = db.data.utilisateurs.find((u) => u.id === req.proprietaireId);
  if (!utilisateur) return res.status(404).json({ erreur: 'Utilisateur introuvable' });

  const { ancienMotDePasse, nouveauMotDePasse } = req.body;

  const valide = await bcrypt.compare(ancienMotDePasse || '', utilisateur.motDePasseHash);
  if (!valide) {
    return res.status(401).json({ erreur: 'Mot de passe actuel incorrect' });
  }

  if (!nouveauMotDePasse || nouveauMotDePasse.length < 8) {
    return res.status(400).json({ erreur: 'Le nouveau mot de passe doit contenir au moins 8 caractères' });
  }

  utilisateur.motDePasseHash = await bcrypt.hash(nouveauMotDePasse, 10);
  await db.write();
  res.json({ message: 'Mot de passe modifié avec succès' });
});

// --- FAVORIS ---

app.get('/api/favoris', verifierProprietaire, (req, res) => {
  const utilisateur = db.data.utilisateurs.find((u) => u.id === req.proprietaireId);
  res.json(utilisateur?.favoris || []);
});

app.post('/api/favoris/:id/basculer', verifierProprietaire, async (req, res) => {
  const utilisateur = db.data.utilisateurs.find((u) => u.id === req.proprietaireId);
  if (!utilisateur) return res.status(404).json({ erreur: 'Utilisateur introuvable' });

  utilisateur.favoris ||= [];
  const logementId = Number(req.params.id);

  if (utilisateur.favoris.includes(logementId)) {
    utilisateur.favoris = utilisateur.favoris.filter((f) => f !== logementId);
  } else {
    utilisateur.favoris.push(logementId);
  }

  await db.write();
  res.json({ favoris: utilisateur.favoris });
});

// --- LOGEMENTS ---

function retirerInfosSensibles(logement) {
  const { telephoneProprietaire, proprietaireId, pieceIdentiteRecto, pieceIdentiteVerso, justificatifPropriete, ...donneesPubliques } = logement;
  return donneesPubliques;
}

app.get('/api/logements', (req, res) => {
  res.json(db.data.logements.map(retirerInfosSensibles));
});

app.get('/api/admin/logements', verifierAdmin, (req, res) => {
  res.json(db.data.logements);
});

app.get('/api/mes-logements', verifierProprietaire, (req, res) => {
  const mesLogements = db.data.logements.filter((l) => l.proprietaireId === req.proprietaireId);
  res.json(mesLogements);
});

app.post('/api/logements', verifierProprietaire, uploadAnnonce, async (req, res) => {
  const proprietaire = db.data.utilisateurs.find((u) => u.id === req.proprietaireId);
  const fichiers = req.files || {};

  const photos = (fichiers.photos || []).map((f) => `/uploads/${f.filename}`);
  const pieceIdentiteRecto = fichiers.pieceIdentiteRecto?.[0] ? `/uploads/${fichiers.pieceIdentiteRecto[0].filename}` : null;
  const pieceIdentiteVerso = fichiers.pieceIdentiteVerso?.[0] ? `/uploads/${fichiers.pieceIdentiteVerso[0].filename}` : null;
  const justificatifPropriete = fichiers.justificatifPropriete?.[0] ? `/uploads/${fichiers.justificatifPropriete[0].filename}` : null;

  const prix = Number(req.body.prix);
  if (!req.body.titre || !req.body.secteur || !prix || prix <= 0) {
    return res.status(400).json({ erreur: 'Champs obligatoires manquants ou invalides' });
  }

  if (!pieceIdentiteRecto || !pieceIdentiteVerso || !justificatifPropriete) {
    return res.status(400).json({ erreur: 'La pièce d\'identité (recto/verso) et le justificatif de propriété sont obligatoires' });
  }

  const nouveauLogement = {
    id: Date.now(),
    titre: req.body.titre,
    secteur: req.body.secteur,
    type: req.body.type,
    prix,
    chambres: Math.max(0, Number(req.body.chambres) || 0),
    salons: Math.max(0, Number(req.body.salons) || 0),
    description: req.body.description || '',
    equipements: req.body.equipements ? JSON.parse(req.body.equipements) : [],
    telephoneProprietaire: proprietaire.telephone,
    proprietaireId: proprietaire.id,
    photos,
    pieceIdentiteRecto,
    pieceIdentiteVerso,
    justificatifPropriete,
    datePublication: new Date().toISOString(),
    disponibilite: 'disponible',
    statut: 'en_attente',
  };

  db.data.logements.push(nouveauLogement);
  await db.write();
  res.status(201).json(nouveauLogement);
});

// Modification par le PROPRIETAIRE (champs texte uniquement, repasse en attente si déjà validée)
app.patch('/api/mes-logements/:id', verifierProprietaire, async (req, res) => {
  const id = Number(req.params.id);
  const logement = db.data.logements.find((l) => l.id === id);

  if (!logement) return res.status(404).json({ erreur: 'Logement introuvable' });
  if (logement.proprietaireId !== req.proprietaireId) {
    return res.status(403).json({ erreur: 'Vous ne pouvez modifier que vos propres annonces' });
  }

  const { titre, secteur, type, prix, chambres, salons, description } = req.body;

  if (!titre || !secteur || !prix || Number(prix) <= 0) {
    return res.status(400).json({ erreur: 'Champs obligatoires manquants ou invalides' });
  }

  logement.titre = titre;
  logement.secteur = secteur;
  logement.type = type;
  logement.prix = Number(prix);
  logement.chambres = Math.max(0, Number(chambres) || 0);
  logement.salons = Math.max(0, Number(salons) || 0);
  logement.description = description || '';

  if (logement.statut === 'validee') {
    logement.statut = 'en_attente';
    logement.motifRefus = null;
  }

  await db.write();
  res.json(logement);
});

// Modification par l'ADMIN (statut, disponibilité, motif de refus...)
app.patch('/api/logements/:id', verifierAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const logement = db.data.logements.find((l) => l.id === id);
  if (!logement) return res.status(404).json({ erreur: 'Logement introuvable' });
  Object.assign(logement, req.body);
  await db.write();
  res.json(logement);
});

app.delete('/api/logements/:id', verifierProprietaire, async (req, res) => {
  const id = Number(req.params.id);
  const logement = db.data.logements.find((l) => l.id === id);

  if (!logement) return res.status(404).json({ erreur: 'Logement introuvable' });
  if (logement.proprietaireId !== req.proprietaireId) {
    return res.status(403).json({ erreur: 'Vous ne pouvez supprimer que vos propres annonces' });
  }

  db.data.logements = db.data.logements.filter((l) => l.id !== id);
  await db.write();
  res.status(204).end();
});

// --- STATISTIQUES PUBLIQUES ---

app.get('/api/stats/secteurs', (req, res) => {
  const comptage = {};
  db.data.demandes.forEach((demande) => {
    const logement = db.data.logements.find((l) => l.id === demande.logementId);
    if (logement) {
      comptage[logement.secteur] = (comptage[logement.secteur] || 0) + 1;
    }
  });

  const classement = Object.entries(comptage)
    .map(([secteur, total]) => ({ secteur, total }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 5);

  res.json(classement);
});

// --- DEMANDES DE CONTACT ---

app.get('/api/demandes', verifierAdmin, (req, res) => {
  res.json(db.data.demandes);
});

app.post('/api/demandes', async (req, res) => {
  const { logementId, logementTitre, nom, telephone } = req.body;

  if (!/^\d{9}$/.test(telephone || '')) {
    return res.status(400).json({ erreur: 'Le numéro de téléphone doit contenir exactement 9 chiffres' });
  }

  const nouvelleDemande = {
    id: Date.now(),
    logementId,
    logementTitre,
    nom,
    telephone,
    statut: 'nouvelle',
  };
  db.data.demandes.push(nouvelleDemande);
  await db.write();
  res.status(201).json(nouvelleDemande);
});

app.patch('/api/demandes/:id', verifierAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const demande = db.data.demandes.find((d) => d.id === id);
  if (!demande) return res.status(404).json({ erreur: 'Demande introuvable' });
  Object.assign(demande, req.body);
  await db.write();
  res.json(demande);
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`);
});