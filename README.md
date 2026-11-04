# MedTalk (Supabase version)

End-to-end encrypted medical consultations. Patients ask for a consultation, verified medical professionals pick them up from a waiting room, and only those two people can read what is said. Supabase stores accounts, consultations, messages, files and health cards, but only as public keys, password-locked private keys, ciphertext and encrypted bytes.

**Two kinds of users (plus the admin):**
- **Patient:** asks for a consultation (topic + urgency), sees only their own consultations, keeps an encrypted health card, and can read past consultations in History.
- **Medical professional:** signs up with a specialty and PRC license number, waits for the admin to verify them, then sees the waiting room (most urgent first, with waiting times), accepts patients and can end a consultation with an encrypted visit summary.
- **Admin:** verifies or unverifies professionals, deletes accounts, reads reports, and sees every consultation, but only as ciphertext.

**Features:** consultation requests with topic and urgency, waiting room, encrypted chat, encrypted photos and files, encrypted health card (blood type, allergies, medicines, conditions, emergency contact) that the patient can share in a chat, encrypted visit summary card (assessment, advice, medicines, follow-up), read-only history, online status, typing indicator, "Seen", disappearing messages, encrypted reactions, delete for everyone, report to admin, profiles (picture, bio, background, specialty for professionals), stay logged in, dark mode, About page with the team, emergency reminder (call 911).

**Changing the team list:** open `index.html`, search for `const TEAM`, and edit the names, roles and one-line descriptions. **Changing the topics:** search for `const TOPICS`.

## Updating from LANLORDS Messenger (about 3 minutes)

1. **Update the database.** In Supabase open **SQL Editor → New query**, paste all of the new `schema.sql`, and click **Run**. It is safe to run again. Existing accounts become **patients**; nobody's account or key is deleted. Old friend chats stay in the database (the admin still sees them as ciphertext) but no longer show in the app, because messages now belong to a consultation.
2. **Update the site.** In your GitHub repo, replace `index.html` with the new one (on GitHub: **Add file → Upload files**, drop it in, and commit). Vercel redeploys on its own in about a minute. Keep `config.js` as it is.
3. **Make professionals.** New professionals pick **Medical professional** when they sign up. To turn an existing account into a professional instead, run in the SQL Editor:
   `update public.profiles set role = 'doctor', specialty = 'General medicine', license = '0123456' where username = 'their_username';`
4. **Verify them.** Log in as `admin` and tap **Verify** next to each professional. Until then they cannot see any patient.

## First-time setup (about 10 minutes)

1. **Create the tables.** In Supabase open **SQL Editor → New query**, paste all of `schema.sql`, and click **Run**.
2. **Turn off email confirmation.** Open **Authentication → Sign In / Providers**. Under **User Signups**, keep **Allow new users to sign up** ON and switch **Confirm email** OFF, then click **Save**.
3. **Key.** Already filled in `config.js`. Never put the secret/service_role key there.
4. **Put it online:** push the folder to a GitHub repo, then in Vercel click **Add New → Project**, import the repo, and click **Deploy** (no build settings needed).
5. **Make the admin.** Create an account with username `admin`, then in the SQL Editor run:
   `update public.profiles set role = 'admin' where username = 'admin';`
   Log out and back in as `admin` to open the admin console.

## Demo script (three browsers or phones)

1. **Professional signs up** (Medical professional, specialty, license). The app says it is waiting for verification.
2. **Admin verifies** them in the console. The professional's screen switches to the waiting room by itself.
3. **Patient signs up** and taps **New consultation**: pick "Skin" and "Urgent". The request pops up in the waiting room, at the top, with how long they have been waiting.
4. **Professional accepts.** The patient gets a notice and the encrypted chat opens. Show typing, "Seen", and send a photo.
5. **Patient shares the health card** (clipboard icon next to the message box). It arrives as a card only the professional can read.
6. Tap the **eye icon** to show what the server actually stores. Open the **i** panel to compare safety numbers and turn on disappearing messages.
7. **Professional sends a visit summary** (clipboard icon) and ends the consultation. The patient sees the summary card, and the chat moves to History as read-only.
8. **Log in as a second patient:** they see nothing of the first patient, not even that the first patient exists.
9. **Admin:** every consultation is listed with topic and urgency, but the messages are scrambled and **Try to decrypt as admin** fails. "Messages the admin can read: 0".

## How it is secured
- An ECDH P-256 key pair is made in the browser. The private key is encrypted with the user's password (PBKDF2, 250,000 rounds) before upload.
- Supabase Auth only receives a one-way code derived from the password, so the server cannot unlock the private key.
- Each message uses a fresh AES-256-GCM key (HKDF with a random salt), padded to 64-byte blocks so lengths leak less. Every message is also sealed to its consultation, so it cannot be moved into another one.
- Photos and files are encrypted with the same per-message key before upload; storage only sees random bytes.
- The health card is encrypted with a key only the patient's own private key can make, so not even the admin can read it. Sharing it sends a copy encrypted for the professional.
- Row Level Security (checked by the database, not just the app):
  - patients read only their own consultations and messages;
  - profiles are no longer public: you see yourself, verified professionals, the people in your own consultations, and (verified professionals only) patients who are waiting;
  - only patients can ask for a consultation, only verified professionals can accept, two professionals cannot take the same patient, nobody can hand a patient to someone else, and an ended consultation cannot be reopened;
  - messages can only be sent inside an open consultation, between its two people;
  - nobody can sign up as admin or as an already-verified professional, or change their own role.
- Disappearing messages: the server stamps the expiry time, hides expired messages at once, and a cleanup job deletes them every minute.
- Safety numbers and key-change warnings catch swapped keys.

This is a school project, not a real medical service.
