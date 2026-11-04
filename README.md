# MedTalk (Supabase version)

End-to-end encrypted medical consultations. Patients ask for a consultation, verified medical professionals pick them up from a waiting room, and only those two people can read what is said. Supabase stores accounts, consultations, messages, files and health cards, but only as public keys, password-locked private keys, ciphertext and encrypted bytes.

**Three kinds of users (plus the admin):**
- **Patient:** asks for a consultation (topic + urgency), sees only their own consultations, keeps an encrypted health card, and can read past consultations in History.
- **Medical professional:** signs up with a specialty and PRC license number, waits for the admin to verify them, then sees the waiting room (most urgent first, with waiting times), accepts patients and can end a consultation with an encrypted visit summary.
- **Clinic staff (front desk):** sees the waiting room and the verified professionals (who is online, how many patients each has), and assigns a professional to each patient. Staff never see what is said.
- **Admin:** makes staff accounts, verifies or unverifies professionals, deletes accounts, reads reports, and sees every consultation, but only as ciphertext.

**Features:** consultation requests with topic and urgency, waiting room, encrypted chat, encrypted photos and files, encrypted health card (blood type, allergies, medicines, conditions, emergency contact) that the patient can share in a chat, encrypted visit summary card (assessment, advice, medicines, follow-up), read-only history, online status, typing indicator, "Seen", disappearing messages, encrypted reactions, delete for everyone, voice and video calls, login alerts, two-factor authentication, password reset by email with a recovery key, report to admin, profiles (picture, bio, background, specialty for professionals), stay logged in, light clinical theme with a dark mode switch, About page with the team, emergency reminder (call 911).

**Changing the team list:** open `index.html`, search for `const TEAM`, and edit the names, roles and one-line descriptions. **Changing the topics:** search for `const TOPICS`.

## Updating to the security, calls and staff version (about 15 minutes)

1. **Update the database.** In Supabase open **SQL Editor → New query**, paste all of the new `schema.sql`, and click **Run**. It is safe to run again and keeps every account and message.
2. **Update the site.** Replace `index.html` in your GitHub repo (**Add file → Upload files**, then commit). Vercel redeploys in about a minute. Keep `config.js`.
3. **Send emails from Gmail** (needed for "Forgot password?" and for adding an email; Supabase's built-in sender only mails your own team).
   1. On the Gmail account you want to send from, turn on **2-Step Verification**, then open https://myaccount.google.com/apppasswords, make an app password called "MedTalk" and copy the 16 letters.
   2. In Supabase open **Authentication → Emails → SMTP Settings**, switch on **Enable custom SMTP** and fill in: sender email = your Gmail address, sender name = MedTalk, host = `smtp.gmail.com`, port = `465`, username = your Gmail address, password = the 16-letter app password. Save.
   3. Open **Authentication → URL Configuration**. Set **Site URL** to your Vercel address (for example `https://medtalk.vercel.app`) and add the same address to **Redirect URLs**. The reset link only works for addresses listed here.
   4. Open **Authentication → Sign In / Providers → Email** and switch **Secure email change** OFF. Old accounts have a made-up address, so the confirmation must only go to the new email. Keep **Confirm email** OFF as before.
4. **2FA.** Nothing to set up: authenticator-app 2FA (TOTP) is on by default under **Authentication → Multi-Factor**. If someone gets "2FA is switched off", turn TOTP on there.
5. **Make staff.** The person signs up as a normal patient. Log in as `admin`, find them under Accounts and tap **Make staff**. They see the front desk the next time they log in.
6. **Calls through strict networks (optional).** Calls go straight between the two browsers and work on most home WiFi and mobile data. Some school or office networks block that. If calls say "could not connect", get free TURN details (for example from metered.ca) and add them to `config.js`:
   `turn: [{ urls: 'turn:YOUR-SERVER:443?transport=tcp', username: '...', credential: '...' }],`
   The call is still end-to-end encrypted when it goes through TURN.

If **Change password** shows "Supabase said: …", read the message: "reauthentication" means **Secure password change** is on (MedTalk logs you in again and retries by itself), and a "password requirements" message means you should clear **Password requirements** under **Authentication → Sign In / Providers → Email** (MedTalk sends Supabase a long scrambled code, never your real password). **Forgot password?** only works for accounts that have an email: old accounts add one first under the shield icon.

> **Forgot password is turned off** in this version, together with the sign-up email and the recovery key settings, so you can skip the Gmail SMTP step (step 3). Passwords can still be changed under the shield icon. To bring it back, open `index.html`, search for `RESET_BY_EMAIL`, set it to `true`, and do step 3.

### What is new
- **Login alerts.** A wrong password, a right password with a wrong 2FA code, 5 wrong tries (the account locks for 15 minutes), a login from a new device, or a password, key or 2FA change from another device shows a "Security alert" with the time, browser and IP address the next time the owner opens MedTalk, or right away if they are online. Your own typos just before logging in are not shown.
- **Two-factor authentication.** Shield icon → **Turn on 2FA** → scan the QR code with Google Authenticator or Microsoft Authenticator → type the code. From then on the database itself refuses to hand out your locked key, consultations or messages until the 6-digit code is entered, so a stolen password is not enough.
- **Forgot password.** Login screen → **Forgot password?** → type the email → open the link → type the **recovery key** and a new password. Every new account gets a recovery key when it signs up; older accounts make one under the shield icon (needs the current password). Without a recovery key the user can still reset, but MedTalk makes new encryption keys and old consultations can no longer be read. That is the price of end-to-end encryption: nobody, not even the admin, holds a copy of your key.
- **Security and login** (shield icon, for everyone): 2FA on or off, add or change the reset email, make a new recovery key, change password, and the recent security activity list.
- **Voice and video calls, Messenger style** inside an open consultation (phone and camera icons at the top of the chat): blurred profile picture behind the call, "Calling…" then "Ringing…", an incoming call screen with Decline, Answer (voice) and Video, then camera on or off at any time (even in a voice call), flip camera on phones, share screen on computers, mute, and minimize to a small floating window so you can keep chatting. You also see when the other person is muted. The chat gets a call card ("Video call · 3:12" or "Missed voice call") with a **Call back** button.
- **Only staff assign patients.** Professionals no longer browse a waiting room. Their **Requests** tab only shows patients who picked them in **Choose a professional**, and they can **Accept** or **Pass**. Everyone else ("First available", passed requests, or a chosen professional who did not accept within 10 minutes) is assigned by the front desk. The database enforces this too: a professional cannot see or accept a request that does not name them.
- **Patients can pick their professional.** New consultation → **Choose a professional**: each one shows specialty, online or offline, "Your professional before" and "Good match" for the chosen topic. The patient can tap **Let front desk choose** while waiting. History has **Consult again** for the same professional.
- **Delete or save a consultation.** Open an ended consultation → details panel: **Save as PDF** (chat and visit summary, decrypted on your device), **Remove from my history** (only for you), and for patients **Delete for everyone** (messages and files, cannot be undone; tap twice to confirm).
- **Daily report.** Professionals: calendar icon next to the shield → pick a day → patients, times, topics and visit summaries → **Save as PDF** or **Download CSV** (opens in Excel). Staff: **Daily report** on the front desk → requests, who was assigned, how long patients waited. Staff never see what was said.
- **Book a time.** New consultation → **When?** → **Book a time** → pick a date and a 30-minute slot. With a chosen professional, only times inside their clinic hours are offered. The appointment shows as "📅 Tomorrow 3:00 PM" for everyone, doctors get a **Today's appointments** section, and both sides get a reminder 10 minutes before.
- **Clinic hours and Away.** Professionals: profile → **Availability** → tick the clinic days, set the hours, or switch on **I'm away**. Patients see "In clinic hours", "Away" and the hours before choosing, and staff see them when assigning.
- **Printable prescription.** When a visit summary has medicines (one per line), the card and the details panel get **Print prescription**: an Rx slip with the professional's name, specialty, PRC license number, date, the medicines, instructions and a signature line. Save it as PDF or print it.
- **Admin charts.** The admin console has an **Activity** panel: consultations per day for the last 14 days, top topics, average wait by urgency, and how patients were matched. The accounts table now uses the full width.
- **Install as an app.** On Android and computers (Chrome or Edge) a tip at the top of the list offers **Install**; on iPhone it says Share → Add to Home Screen. **Notify me** turns on notifications for messages, calls and appointment reminders while MedTalk is open in the background. A notification only says "New encrypted message", never the text. (Notifications while the app is fully closed would need a push server, which this version does not have.) Upload **manifest.webmanifest, sw.js and the four .png icons** together with index.html.
- **Dark mode switch** (sun and moon toggle) on every screen.
- **Clinic staff** front desk: waiting room with urgency and waiting time, a list of verified professionals with who is online and how many open patients each has, and an **Assign** button. Staff assign everyone who did not choose a professional.
- **Light clinical look** by default. Dark mode is now only used when you tap the moon button (it no longer follows the Windows or phone setting).

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
9. **Staff:** a patient asks for help, the staff account assigns them to a professional from the front desk, and the professional gets "Clinic staff assigned you a new patient".
10. **Call:** in an open consultation tap the camera icon. The other side rings, answers, and the video starts. Hang up and a "Video call · 0:42" line appears in the chat.
11. **Login alert:** on another browser, type the patient's username with a wrong password a few times. When the patient opens MedTalk they get a "Security alert" with the time, browser and IP. Turn on 2FA from the shield icon and show that the right password alone no longer gets in.
12. **Forgot password:** log out, tap **Forgot password?**, open the email, and type the recovery key and a new password. The old messages are all still readable.
13. **Admin:** every consultation is listed with topic and urgency, but the messages are scrambled and **Try to decrypt as admin** fails. "Messages the admin can read: 0".

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
  - nobody can sign up as admin, staff or an already-verified professional, or change their own role.
- Logging in by username: the app sends the login code to a database function that checks it against Supabase's own password hash, writes down failed tries for the owner's alerts, and locks the account for 15 minutes after 5 wrong tries. Only after that does it give back the email needed to sign in, so nobody can look up anyone's email.
- 2FA (TOTP) uses Supabase Auth. Extra "restrictive" database rules refuse every table to a session that has not passed the 2FA step when the account has 2FA on.
- Recovery key: a second copy of the private key, locked with a random 160-bit key that only the user has (PBKDF2 + AES-256-GCM). It is shown once at sign-up and never stored in plain form.
- Calls: WebRTC. The call setup messages are sealed with the consultation's per-message AES keys, and audio and video are encrypted browser to browser (DTLS-SRTP).
- Staff assign through a database function that only accepts waiting patients and verified professionals. Staff can see who is waiting and the topic, never the messages.
- Disappearing messages: the server stamps the expiry time, hides expired messages at once, and a cleanup job deletes them every minute.
- Safety numbers and key-change warnings catch swapped keys.

This is a school project, not a real medical service.
