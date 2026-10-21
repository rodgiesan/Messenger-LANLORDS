# LANLORDS Messenger (Supabase version)

End-to-end encrypted messenger. Supabase stores accounts, friendships, messages and files, but only as public keys, password-locked private keys, ciphertext and encrypted bytes.

**Features:** friends (requests, accept, decline, unfriend), encrypted photos and files, online status, typing indicator, "Seen", disappearing messages, block, report to admin, emoji picker, quick 👍, encrypted emoji reactions, delete a message for everyone, cancel a sent friend request, tap a name in a chat for a small profile card, profiles (picture, bio, background color, picture or GIF, rename yourself), stay logged in after reload, an About page with the team, and an admin console that can delete accounts.

**Changing the team list:** open `index.html`, search for `const TEAM`, and edit the names, roles and one-line descriptions.

## Updating to this version (about 3 minutes)

1. **Update the database.** In Supabase open **SQL Editor → New query**, paste all of the new `schema.sql`, and click **Run**. It is safe to run again; nothing you already have is deleted. It also creates the private `attachments` bucket, the public `avatars` bucket for profile pictures, and the admin's delete-account function.
2. **Update the site.** In your GitHub repo, replace `index.html` with the new one (on GitHub: **Add file → Upload files**, drop it in, and commit). Vercel redeploys on its own in about a minute. Keep `config.js` as it is.
3. **Add each other as friends.** Messages now only go between friends, so each person sends a friend request (Chats tab → Add people) and the other accepts it in the Requests tab. Old chats come back once you are friends.

## First-time setup (about 10 minutes)

1. **Create the tables.** In Supabase open **SQL Editor → New query**, paste all of `schema.sql`, and click **Run**.
2. **Turn off email confirmation.** Open **Authentication → Sign In / Providers**. Under **User Signups**, keep **Allow new users to sign up** ON and switch **Confirm email** OFF, then click **Save**. (Usernames are turned into made-up emails, so no real email is ever sent.) If sign-up says "Signups not allowed", the first switch is off.
3. **Key.** Already filled in `config.js`. Never put the secret/service_role key there.
4. **Put it online** (pick one):
   - **Vercel:** push the folder to a GitHub repo, then in Vercel click **Add New → Project**, import the repo, and click **Deploy** (no build settings needed).
   - **Netlify Drop:** go to app.netlify.com/drop and drag this whole folder onto the page.
5. **Make the admin.** In the app, create an account with username `admin`. Then in the SQL Editor run:
   `update public.profiles set role = 'admin' where username = 'admin';`
   Log out and back in as `admin` to open the admin console.

## Demo script (two phones or two browsers)

1. Make two accounts. One sends a friend request; the other accepts it under **Requests**.
2. Chat. Show the typing dots, the green online dot and "Seen" under the last message.
3. Send a photo with the paperclip. Then tap the **eye icon** to show what the server actually stores.
4. Open the chat details (the **i** icon): compare the safety numbers on both screens, and turn on **Disappearing messages → 1 minute**.
5. Log in as `admin`: every account and conversation is listed, but the messages and files are scrambled, and **Try to decrypt as admin** fails.

## How it is secured
- An ECDH P-256 key pair is made in the browser. The private key is encrypted with the user's password (PBKDF2, 250,000 rounds) before upload.
- Supabase Auth only receives a one-way code derived from the password, so the server cannot unlock the private key.
- Each message uses a fresh AES-256-GCM key (HKDF with a random salt), padded to 64-byte blocks so lengths leak less.
- Photos and files are encrypted with the same per-message key before upload. The file name and type travel inside the encrypted message, so storage only sees random bytes named like `1730000000000-ab12cd.bin`.
- Row Level Security: only friends can message each other, only the invited person can accept a request, a block can only be lifted by the person who made it, and users read only their own chats and files.
- Disappearing messages: the server stamps the expiry time, hides expired messages at once, and a cleanup job deletes them every minute.
- Reports go to the admin only; the admin can list everything but only as ciphertext.
- Safety numbers and key-change warnings catch swapped keys.
