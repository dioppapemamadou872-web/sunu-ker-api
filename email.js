import nodemailer from 'nodemailer';

const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = Number(process.env.SMTP_PORT) || 587;
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const EMAIL_FROM = process.env.EMAIL_FROM || '"DëkuWaay" <contact@dekuwaay.com>';

let transporter = null;

if (SMTP_USER && SMTP_PASS) {
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS,
    },
  });
}

export async function envoyerEmail({ to, subject, html, text }) {
  if (!to) return;
  if (!transporter) {
    console.log(`[EMAIL SIMULÉ - SMTP NON CONFIGURÉ] Destinataire: ${to} | Sujet: ${subject}`);
    return;
  }

  try {
    const info = await transporter.sendMail({
      from: EMAIL_FROM,
      to,
      subject,
      text,
      html,
    });
    console.log(`[EMAIL ENVOYÉ] ID: ${info.messageId} | À: ${to}`);
    return info;
  } catch (error) {
    console.error(`[ERREUR EMAIL] Échec d'envoi à ${to}:`, error.message);
  }
}

// 1. Email de bienvenue propriétaire
export async function envoyerEmailBienvenueProprietaire(proprietaire) {
  const { prenom, nom, email } = proprietaire;
  if (!email) return;

  const subject = 'Bienvenue sur DëkuWaay — Votre espace propriétaire';
  const html = `
    <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f8fafc; color: #1e293b; border-radius: 16px;">
      <div style="text-align: center; padding-bottom: 20px; border-bottom: 1px solid #e2e8f0;">
        <h1 style="color: #2563eb; margin: 0; font-size: 28px; font-weight: 800;">Dëku<span style="color: #10b981;">Waay</span></h1>
        <p style="color: #64748b; font-size: 14px; margin-top: 4px;">La référence immobilière à Dakar</p>
      </div>
      <div style="padding: 24px 0;">
        <h2 style="color: #0f172a; font-size: 20px; margin-bottom: 12px;">Bonjour ${prenom} ${nom} 👋</h2>
        <p style="line-height: 1.6; color: #334155;">Nous sommes ravis de vous compter parmi les bailleurs certifiés de <strong>DëkuWaay</strong>.</p>
        <p style="line-height: 1.6; color: #334155;">Depuis votre espace personnel, vous pouvez désormais publier des annonces de logement, suivre les demandes de locataires et gérer votre profil en toute sécurité.</p>
      </div>
      <div style="background-color: #ffffff; padding: 16px; border-radius: 12px; border: 1px solid #e2e8f0; text-align: center; margin-bottom: 24px;">
        <p style="margin: 0 0 8px 0; font-weight: 600; color: #0f172a;">Prêt à proposer un bien ?</p>
        <a href="https://dekuwaay.com/publier" style="display: inline-block; background-color: #2563eb; color: #ffffff; padding: 12px 24px; border-radius: 10px; text-decoration: none; font-weight: 600; font-size: 14px;">Publier une annonce</a>
      </div>
      <div style="text-align: center; border-top: 1px solid #e2e8f0; padding-top: 16px; font-size: 12px; color: #94a3b8;">
        <p style="margin: 0;">DëkuWaay · Dakar, Sénégal · <a href="https://dekuwaay.com" style="color: #2563eb; text-decoration: none;">dekuwaay.com</a></p>
      </div>
    </div>
  `;

  return envoyerEmail({ to: email, subject, html });
}

// 2. Email statut annonce (Validation / Refus)
export async function envoyerEmailStatutAnnonce(proprietaire, logement, statut, motifRefus) {
  const { prenom, email } = proprietaire;
  if (!email) return;

  const estValidee = statut === 'validee';
  const subject = estValidee
    ? `🎉 Votre annonce "${logement.titre}" est en ligne sur DëkuWaay !`
    : `Mise à jour concernant votre annonce "${logement.titre}"`;

  const html = `
    <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f8fafc; color: #1e293b; border-radius: 16px;">
      <div style="text-align: center; padding-bottom: 20px; border-bottom: 1px solid #e2e8f0;">
        <h1 style="color: #2563eb; margin: 0; font-size: 28px; font-weight: 800;">Dëku<span style="color: #10b981;">Waay</span></h1>
      </div>
      <div style="padding: 24px 0;">
        <h2 style="color: #0f172a; font-size: 20px; margin-bottom: 12px;">Bonjour ${prenom},</h2>
        ${estValidee ? `
          <p style="line-height: 1.6; color: #166534; background-color: #dcfce7; padding: 12px 16px; border-radius: 10px; font-weight: 600;">
            ✅ Bonne nouvelle ! Votre annonce <strong>"${logement.titre}"</strong> (${logement.secteur}) a été vérifiée et validée par notre équipe. Elle est désormais visible publiquement sur notre plateforme.
          </p>
        ` : `
          <p style="line-height: 1.6; color: #991b1b; background-color: #fee2e2; padding: 12px 16px; border-radius: 10px; font-weight: 600;">
            ⚠️ Votre annonce <strong>"${logement.titre}"</strong> nécessite des ajustements avant publication.
          </p>
          <div style="background-color: #ffffff; padding: 14px; border-left: 4px solid #ef4444; border-radius: 6px; margin: 16px 0;">
            <p style="margin: 0; font-size: 14px; color: #475569;"><strong>Motif indiqué par la modération :</strong></p>
            <p style="margin: 4px 0 0 0; font-size: 14px; color: #0f172a;">${motifRefus || 'Fichier ou description non conforme.'}</p>
          </div>
        `}
      </div>
      <div style="text-align: center; border-top: 1px solid #e2e8f0; padding-top: 16px; font-size: 12px; color: #94a3b8;">
        <p style="margin: 0;">L'équipe DëkuWaay · Support: contact@dekuwaay.com</p>
      </div>
    </div>
  `;

  return envoyerEmail({ to: email, subject, html });
}

// 3. Email nouvelle demande de contact locataire pour le propriétaire
export async function envoyerEmailDemandeContact(proprietaire, demande, logement) {
  const { prenom, email } = proprietaire;
  if (!email) return;

  const subject = `🔔 Nouveau locataire intéressé par votre bien "${logement.titre}"`;
  const html = `
    <div style="font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f8fafc; color: #1e293b; border-radius: 16px;">
      <div style="text-align: center; padding-bottom: 20px; border-bottom: 1px solid #e2e8f0;">
        <h1 style="color: #2563eb; margin: 0; font-size: 28px; font-weight: 800;">Dëku<span style="color: #10b981;">Waay</span></h1>
      </div>
      <div style="padding: 24px 0;">
        <h2 style="color: #0f172a; font-size: 20px; margin-bottom: 12px;">Bonjour ${prenom},</h2>
        <p style="line-height: 1.6; color: #334155;">Un locataire a soumis une demande d'information pour votre annonce <strong>"${logement.titre}"</strong> (${logement.secteur}).</p>
        <div style="background-color: #ffffff; padding: 16px; border-radius: 12px; border: 1px solid #e2e8f0; margin: 16px 0;">
          <p style="margin: 0 0 8px 0; font-size: 14px;"><strong>Nom du locataire :</strong> ${demande.prenom || ''} ${demande.nom || ''}</p>
          <p style="margin: 0 0 8px 0; font-size: 14px;"><strong>Téléphone :</strong> ${demande.telephone}</p>
          ${demande.message ? `<p style="margin: 8px 0 0 0; font-size: 14px; color: #475569;"><em>"${demande.message}"</em></p>` : ''}
        </div>
      </div>
      <div style="text-align: center; border-top: 1px solid #e2e8f0; padding-top: 16px; font-size: 12px; color: #94a3b8;">
        <p style="margin: 0;">L'équipe DëkuWaay · <a href="https://dekuwaay.com/mon-espace" style="color: #2563eb; text-decoration: none;">Accéder à mon espace</a></p>
      </div>
    </div>
  `;

  return envoyerEmail({ to: email, subject, html });
}
