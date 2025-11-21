package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	irc "github.com/thoj/go-ircevent"
)

const VERSION = "1.0.2"

// Config structures
type Config struct {
	IRC IRCConfig `toml:"irc"`
	Bot BotConfig `toml:"bot"`
}

type IRCConfig struct {
	Server   string   `toml:"server"`
	Port     int      `toml:"port"`
	SSL      bool     `toml:"ssl"`
	Nick     string   `toml:"nick"`
	RealName string   `toml:"realname"`
	Channels []string `toml:"channels"`
	OperName string   `toml:"oper_name"`
	OperPass string   `toml:"oper_pass"`
}

type BotConfig struct {
	ChallengeTimeout int    `toml:"challenge_timeout"`
	AuthTimeout      int    `toml:"auth_timeout"`
	Database         string `toml:"database"`
	SignNamespace    string `toml:"sign_namespace"`
	EnforceAuth      bool   `toml:"enforce_auth"`
}

// Database structures
type SSHKey struct {
	Fingerprint string    `json:"fingerprint"`
	Key         string    `json:"key"`
	Name        string    `json:"name"`
	Added       time.Time `json:"added"`
}

type User struct {
	Keys     []SSHKey  `json:"keys"`
	LastSeen time.Time `json:"last_seen"`
}

type Database struct {
	Users map[string]*User `json:"users"`
}

// Session structure
type Session struct {
	Nick          string
	Hostmask      string
	Authenticated bool
	JoinTime      time.Time
	WarningGiven  bool
	KickScheduled bool
	GracePeriod   bool // Don't enforce immediately on bot restart
}

// Challenge structure
type Challenge struct {
	String    string
	CreatedAt time.Time
	IsNewUser bool
	KeyData   string
	KeyName   string
}

// Signature buffer
type SignatureBuffer struct {
	Lines     []string
	StartedAt time.Time
}

// Bot state
type KeyServ struct {
	config          Config
	db              *Database
	ircConn         *irc.Connection
	challenges      map[string]*Challenge
	sigBuffers      map[string]*SignatureBuffer
	sessions        map[string]*Session
	isOper          bool
	startupComplete bool
}

func main() {
	log.Printf("KeyServ v%s starting...", VERSION)

	var config Config
	if _, err := toml.DecodeFile("config.toml", &config); err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	bot := &KeyServ{
		config:          config,
		challenges:      make(map[string]*Challenge),
		sigBuffers:      make(map[string]*SignatureBuffer),
		sessions:        make(map[string]*Session),
		isOper:          false,
		startupComplete: false,
	}

	bot.loadDatabase()
	bot.setupIRC()

	// Start session monitor
	go bot.monitorSessions()

	log.Printf("Connecting to %s:%d", config.IRC.Server, config.IRC.Port)
	if err := bot.ircConn.Connect(fmt.Sprintf("%s:%d", config.IRC.Server, config.IRC.Port)); err != nil {
		log.Fatalf("Error connecting: %v", err)
	}

	bot.ircConn.Loop()
}

func (ks *KeyServ) setupIRC() {
	ks.ircConn = irc.IRC(ks.config.IRC.Nick, ks.config.IRC.Nick)
	if ks.ircConn == nil {
		log.Fatal("Failed to create IRC connection")
	}

	ks.ircConn.RealName = ks.config.IRC.RealName
	ks.ircConn.UseTLS = ks.config.IRC.SSL
	ks.ircConn.VerboseCallbackHandler = false
	ks.ircConn.Debug = false

	if ks.config.IRC.SSL {
		ks.ircConn.TLSConfig = &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         ks.config.IRC.Server,
		}
	}

	// Handle connection
	ks.ircConn.AddCallback("001", func(e *irc.Event) {
		log.Println("✓ Connected to IRC")

		// Authenticate as oper if configured
		if ks.config.IRC.OperName != "" && ks.config.IRC.OperPass != "" {
			log.Println("Attempting oper authentication...")
			ks.ircConn.SendRaw(fmt.Sprintf("OPER %s %s", ks.config.IRC.OperName, ks.config.IRC.OperPass))
		} else {
			log.Println("⚠ No oper credentials configured - SANICK will not work")
			// Join channels immediately if not using oper
			for _, channel := range ks.config.IRC.Channels {
				ks.ircConn.Join(channel)
				log.Printf("✓ Joined %s", channel)
			}
			ks.discoverExistingUsers()
		}
	})

	// Handle oper authentication success
	ks.ircConn.AddCallback("381", func(e *irc.Event) {
		log.Println("✓ Authenticated as IRC operator")
		ks.isOper = true

		// Join channels after becoming oper
		for _, channel := range ks.config.IRC.Channels {
			ks.ircConn.Join(channel)
			log.Printf("✓ Joined %s", channel)
		}

		// Discover users already in channel
		ks.discoverExistingUsers()
	})

	// Handle oper authentication failure
	ks.ircConn.AddCallback("491", func(e *irc.Event) {
		log.Println("✗ Oper authentication failed - continuing without SANICK privileges")
		ks.isOper = false

		// Join channels anyway
		for _, channel := range ks.config.IRC.Channels {
			ks.ircConn.Join(channel)
			log.Printf("✓ Joined %s", channel)
		}
		ks.discoverExistingUsers()
	})

	// Handle WHO replies for discovering existing users
	ks.ircConn.AddCallback("352", func(e *irc.Event) {
		// WHO reply: 352 <requester> <channel> <user> <host> <server> <nick> <flags> :<hopcount> <realname>
		if len(e.Arguments) >= 6 {
			nick := e.Arguments[5]
			user := e.Arguments[2]
			host := e.Arguments[3]
			hostmask := user + "@" + host

			// Ignore our own nick
			if nick == ks.config.IRC.Nick {
				return
			}

			// Check if nick is registered
			if _, exists := ks.db.Users[nick]; exists {
				// Create session with grace period
				if _, sessionExists := ks.sessions[hostmask]; !sessionExists {
					ks.sessions[hostmask] = &Session{
						Nick:          nick,
						Hostmask:      hostmask,
						Authenticated: false,
						JoinTime:      time.Now(),
						WarningGiven:  false,
						KickScheduled: false,
						GracePeriod:   true, // Don't enforce immediately
					}
					log.Printf("Discovered registered user %s already in channel (grace period enabled)", nick)
				}
			}
		}
	})

	// Handle end of WHO list
	ks.ircConn.AddCallback("315", func(e *irc.Event) {
		if !ks.startupComplete {
			ks.startupComplete = true
			log.Println("✓ Startup complete, discovered all existing users")
		}
	})

	// Monitor joins
	ks.ircConn.AddCallback("JOIN", func(e *irc.Event) {
		nick := e.Nick
		hostmask := e.User + "@" + e.Host

		// Ignore bot's own joins
		if nick == ks.config.IRC.Nick {
			return
		}

		// Check if nick is registered
		if user, exists := ks.db.Users[nick]; exists {
			// Create session (no grace period for new joins)
			ks.sessions[hostmask] = &Session{
				Nick:          nick,
				Hostmask:      hostmask,
				Authenticated: false,
				JoinTime:      time.Now(),
				WarningGiven:  false,
				KickScheduled: false,
				GracePeriod:   false,
			}

			// Send auth reminder
			ks.reply(nick, fmt.Sprintf("This nickname is registered (%d keys on file).", len(user.Keys)))
			ks.reply(nick, fmt.Sprintf("Please authenticate within %d seconds: type 'auth'", ks.config.Bot.AuthTimeout))
			log.Printf("User %s (%s) joined - nick is registered, auth required", nick, hostmask)
		} else {
			log.Printf("User %s (%s) joined - nick not registered", nick, hostmask)
		}
	})

	// Monitor quits/parts
	ks.ircConn.AddCallback("QUIT", func(e *irc.Event) {
		hostmask := e.User + "@" + e.Host
		delete(ks.sessions, hostmask)
	})

	ks.ircConn.AddCallback("PART", func(e *irc.Event) {
		hostmask := e.User + "@" + e.Host
		delete(ks.sessions, hostmask)
	})

	// Monitor nick changes
	ks.ircConn.AddCallback("NICK", func(e *irc.Event) {
		oldNick := e.Nick
		newNick := e.Message()
		hostmask := e.User + "@" + e.Host

		if session, exists := ks.sessions[hostmask]; exists {
			log.Printf("Nick change: %s -> %s", oldNick, newNick)

			// Check if the NEW nick is registered
			if _, newNickRegistered := ks.db.Users[newNick]; newNickRegistered {
				// Update session for the new registered nick
				session.Nick = newNick
				session.JoinTime = time.Now()
				session.Authenticated = false
				session.WarningGiven = false
				session.KickScheduled = false
				session.GracePeriod = false

				// Send auth reminder
				ks.reply(newNick, fmt.Sprintf("This nickname is registered. Please authenticate within %d seconds: type 'auth'", ks.config.Bot.AuthTimeout))
			} else {
				// New nick is NOT registered - delete the session entirely
				delete(ks.sessions, hostmask)
				log.Printf("Nick %s is not registered, session removed", newNick)
			}
		}
	})

	ks.ircConn.AddCallback("PRIVMSG", func(e *irc.Event) {
		nick := e.Nick
		message := e.Message()

		if len(e.Arguments) > 0 && !strings.HasPrefix(e.Arguments[0], "#") {
			ks.handleMessage(nick, message)
		}
	})
}

// Discover users already in channels on startup
func (ks *KeyServ) discoverExistingUsers() {
	// Wait a bit for channels to fully join
	time.Sleep(3 * time.Second)

	// Send WHO for each channel to discover existing users
	for _, channel := range ks.config.IRC.Channels {
		ks.ircConn.SendRaw(fmt.Sprintf("WHO %s", channel))
		log.Printf("Discovering users in %s", channel)
	}
}

func (ks *KeyServ) monitorSessions() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		for hostmask, session := range ks.sessions {
			if session.Authenticated {
				continue
			}

			// Skip grace period users initially
			if session.GracePeriod {
				// After 30 seconds, remove grace period
				if time.Since(session.JoinTime).Seconds() > 30 {
					session.GracePeriod = false
					// Reset join time so they get the full auth timeout
					session.JoinTime = now
					ks.reply(session.Nick, fmt.Sprintf("Please authenticate within %d seconds: type 'auth'", ks.config.Bot.AuthTimeout))
				}
				continue
			}

			timeSinceJoin := now.Sub(session.JoinTime).Seconds()
			timeRemaining := float64(ks.config.Bot.AuthTimeout) - timeSinceJoin

			// Give 30-second warning
			if timeRemaining <= 30 && timeRemaining > 0 && !session.WarningGiven {
				session.WarningGiven = true
				ks.reply(session.Nick, fmt.Sprintf("⚠ Warning: %.0f seconds remaining to authenticate!", timeRemaining))
			}

			// Time's up - enforce auth
			if timeSinceJoin >= float64(ks.config.Bot.AuthTimeout) && !session.KickScheduled {
				session.KickScheduled = true

				if ks.config.Bot.EnforceAuth && ks.isOper {
					// Force nick change using SANICK
					newNick := session.Nick + "_"
					ks.ircConn.SendRaw(fmt.Sprintf("SANICK %s %s", session.Nick, newNick))
					ks.reply(newNick, "Authentication timeout. Your nickname has been changed.")
					ks.reply(newNick, fmt.Sprintf("To reclaim '%s', change back with: /nick %s", session.Nick, session.Nick))
					ks.reply(newNick, "Then authenticate with 'auth'")

					// Announce to channels
					for _, channel := range ks.config.IRC.Channels {
						ks.ircConn.Privmsg(channel, fmt.Sprintf("⚠ %s failed to authenticate (renamed to %s)", session.Nick, newNick))
					}

					log.Printf("Forced nick change: %s -> %s (auth timeout)", session.Nick, newNick)

					// Delete the session - it will be recreated if they change to a registered nick
					delete(ks.sessions, hostmask)
				} else {
					// Just warn without enforcement
					ks.reply(session.Nick, "⚠⚠⚠ AUTHENTICATION TIMEOUT ⚠⚠⚠")
					ks.reply(session.Nick, "This nickname is registered. Please authenticate with 'auth'")

					// Announce to channels
					for _, channel := range ks.config.IRC.Channels {
						ks.ircConn.Privmsg(channel, fmt.Sprintf("⚠ %s is using a registered nickname without authenticating", session.Nick))
					}

					if !ks.isOper && ks.config.Bot.EnforceAuth {
						log.Printf("Auth timeout for %s - cannot enforce (not oper)", session.Nick)
					} else {
						log.Printf("Auth timeout for %s - warning issued (enforcement disabled)", session.Nick)
					}
					delete(ks.sessions, hostmask)
				}
			}
		}
	}
}

func (ks *KeyServ) getSession(nick string) *Session {
	for _, session := range ks.sessions {
		if session.Nick == nick {
			return session
		}
	}
	return nil
}

func (ks *KeyServ) isAuthenticated(nick string) bool {
	session := ks.getSession(nick)
	return session != nil && session.Authenticated
}

func (ks *KeyServ) handleMessage(nick, message string) {
	if buf, exists := ks.sigBuffers[nick]; exists {
		line := strings.TrimSpace(message)
		buf.Lines = append(buf.Lines, line)

		if strings.Contains(message, "-----END SSH SIGNATURE-----") {
			signature := strings.Join(buf.Lines, "\n")
			delete(ks.sigBuffers, nick)
			ks.handleVerify(nick, signature)
			return
		}

		if time.Since(buf.StartedAt).Seconds() > 30 {
			delete(ks.sigBuffers, nick)
			ks.reply(nick, "Signature input timed out. Try 'auth' again.")
			return
		}
		return
	}

	if strings.HasPrefix(message, "-----BEGIN SSH SIGNATURE-----") {
		ks.sigBuffers[nick] = &SignatureBuffer{
			Lines:     []string{strings.TrimSpace(message)},
			StartedAt: time.Now(),
		}
		return
	}

	ks.handleCommand(nick, message)
}

func (ks *KeyServ) handleCommand(nick, message string) {
	parts := strings.Fields(message)
	if len(parts) == 0 {
		return
	}

	command := strings.ToLower(parts[0])

	switch command {
	case "help":
		ks.sendHelp(nick)
	case "version":
		ks.reply(nick, fmt.Sprintf("KeyServ v%s - SSH Key Authentication", VERSION))
	case "auth":
		ks.handleAuth(nick, parts[1:])
	case "add":
		if !ks.isAuthenticated(nick) {
			ks.reply(nick, "⚠ You must authenticate first. Type 'auth'")
			return
		}
		if len(parts) < 2 {
			ks.reply(nick, "Usage: add <ssh-public-key> [name]")
			return
		}
		keyParts := parts[1:]
		keyName := "default"

		if len(keyParts) > 3 {
			lastPart := keyParts[len(keyParts)-1]
			if !strings.Contains(lastPart, "AAAA") && !strings.Contains(lastPart, "====") {
				keyName = lastPart
				keyParts = keyParts[:len(keyParts)-1]
			}
		}

		keyStr := strings.Join(keyParts, " ")
		ks.handleAdd(nick, keyStr, keyName)
	case "remove":
		if !ks.isAuthenticated(nick) {
			ks.reply(nick, "⚠ You must authenticate first. Type 'auth'")
			return
		}
		if len(parts) < 2 {
			ks.reply(nick, "Usage: remove <fingerprint>")
			return
		}
		ks.handleRemove(nick, parts[1])
	case "keys":
		if !ks.isAuthenticated(nick) {
			ks.reply(nick, "⚠ You must authenticate first. Type 'auth'")
			return
		}
		ks.handleKeys(nick)
	case "whoami":
		ks.handleWhoami(nick)
	case "info":
		if len(parts) < 2 {
			ks.reply(nick, "Usage: info <nickname>")
			return
		}
		ks.handleInfo(nick, parts[1])
	default:
		ks.reply(nick, "Unknown command. Type 'help' for available commands.")
	}
}

func (ks *KeyServ) handleAuth(nick string, args []string) {
	user, exists := ks.db.Users[nick]

	if !exists || len(user.Keys) == 0 {
		if len(args) == 0 {
			ks.reply(nick, "Welcome! To register this nickname:")
			ks.reply(nick, "  auth <your-ssh-public-key> [name]")
			ks.reply(nick, "Example: auth ssh-ed25519 AAAAC3... laptop")
			ks.reply(nick, "Get your key: cat ~/.ssh/id_ed25519.pub")
			return
		}

		keyParts := args
		keyName := "default"

		if len(keyParts) > 3 {
			lastPart := keyParts[len(keyParts)-1]
			if !strings.Contains(lastPart, "AAAA") && !strings.Contains(lastPart, "====") {
				keyName = lastPart
				keyParts = keyParts[:len(keyParts)-1]
			}
		}

		keyStr := strings.Join(keyParts, " ")

		if !strings.HasPrefix(keyStr, "ssh-") && !strings.HasPrefix(keyStr, "ecdsa-") {
			ks.reply(nick, "Invalid SSH key. Must start with ssh-rsa, ssh-ed25519, etc.")
			return
		}

		fingerprint, err := ks.getKeyFingerprint(keyStr)
		if err != nil {
			ks.reply(nick, fmt.Sprintf("Error: %v", err))
			return
		}

		challenge := ks.generateChallenge()
		ks.challenges[nick] = &Challenge{
			String:    challenge,
			CreatedAt: time.Now(),
			IsNewUser: true,
			KeyData:   keyStr,
			KeyName:   keyName,
		}

		ks.reply(nick, fmt.Sprintf("Key: %s (%s)", fingerprint[:20]+"...", keyName))
		ks.reply(nick, "Run this command:")
		ks.reply(nick, fmt.Sprintf("  echo \"%s\" | ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n %s", challenge, ks.config.Bot.SignNamespace))
		ks.reply(nick, "Then paste the entire signature (expires in 5 min)")
		return
	}

	challenge := ks.generateChallenge()
	ks.challenges[nick] = &Challenge{
		String:    challenge,
		CreatedAt: time.Now(),
		IsNewUser: false,
	}

	ks.reply(nick, "Run this command:")
	ks.reply(nick, fmt.Sprintf("  echo \"%s\" | ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n %s", challenge, ks.config.Bot.SignNamespace))
	ks.reply(nick, "Then paste signature (expires in 5 min)")
}

func (ks *KeyServ) handleVerify(nick, signature string) {
	challenge, exists := ks.challenges[nick]
	if !exists {
		ks.reply(nick, "No active challenge. Use 'auth' first.")
		return
	}

	if time.Since(challenge.CreatedAt).Seconds() > float64(ks.config.Bot.ChallengeTimeout) {
		delete(ks.challenges, nick)
		ks.reply(nick, "Challenge expired. Run 'auth' again.")
		return
	}

	if challenge.IsNewUser {
		if ks.verifySignature(challenge.String, signature, challenge.KeyData) {
			if ks.db.Users == nil {
				ks.db.Users = make(map[string]*User)
			}

			fingerprint, _ := ks.getKeyFingerprint(challenge.KeyData)

			ks.db.Users[nick] = &User{
				Keys: []SSHKey{{
					Fingerprint: fingerprint,
					Key:         challenge.KeyData,
					Name:        challenge.KeyName,
					Added:       time.Now(),
				}},
				LastSeen: time.Now(),
			}
			ks.saveDatabase()
			delete(ks.challenges, nick)

			// Mark session as authenticated
			session := ks.getSession(nick)
			if session == nil {
				// Create session if user authenticated without joining
				session = &Session{
					Nick:          nick,
					Hostmask:      "unknown",
					Authenticated: true,
					JoinTime:      time.Now(),
					WarningGiven:  false,
					KickScheduled: false,
					GracePeriod:   false,
				}
				ks.sessions["auth:"+nick] = session
			} else {
				session.Authenticated = true
			}

			ks.reply(nick, fmt.Sprintf("✓ Registered and authenticated! (%s)", challenge.KeyName))
			for _, channel := range ks.config.IRC.Channels {
				ks.ircConn.Privmsg(channel, fmt.Sprintf("✓ %s authenticated via SSH", nick))
			}
			log.Printf("New user registered: %s", nick)
			return
		}

		ks.reply(nick, "✗ Verification failed. Make sure you're signing with the correct key.")
		return
	}

	user, exists := ks.db.Users[nick]
	if !exists || len(user.Keys) == 0 {
		ks.reply(nick, "No keys registered.")
		return
	}

	for _, key := range user.Keys {
		if ks.verifySignature(challenge.String, signature, key.Key) {
			delete(ks.challenges, nick)

			// Mark session as authenticated
			session := ks.getSession(nick)
			if session == nil {
				// Create session if user authenticated without joining
				session = &Session{
					Nick:          nick,
					Hostmask:      "unknown",
					Authenticated: true,
					JoinTime:      time.Now(),
					WarningGiven:  false,
					KickScheduled: false,
					GracePeriod:   false,
				}
				ks.sessions["auth:"+nick] = session
			} else {
				session.Authenticated = true
			}

			// Update last seen
			user.LastSeen = time.Now()
			ks.saveDatabase()

			ks.reply(nick, fmt.Sprintf("✓ Authenticated! (%s)", key.Name))

			for _, channel := range ks.config.IRC.Channels {
				ks.ircConn.Privmsg(channel, fmt.Sprintf("✓ %s authenticated via SSH", nick))
			}
			log.Printf("User authenticated: %s with key %s", nick, key.Name)
			return
		}
	}

	ks.reply(nick, "✗ Verification failed. Signature doesn't match any registered keys.")
}

func (ks *KeyServ) handleAdd(nick, keyStr, keyName string) {
	user, exists := ks.db.Users[nick]
	if !exists || len(user.Keys) == 0 {
		ks.reply(nick, "Use 'auth' first to register your initial key.")
		return
	}

	if !strings.HasPrefix(keyStr, "ssh-") && !strings.HasPrefix(keyStr, "ecdsa-") {
		ks.reply(nick, "Invalid SSH key format.")
		return
	}

	fingerprint, err := ks.getKeyFingerprint(keyStr)
	if err != nil {
		ks.reply(nick, fmt.Sprintf("Error: %v", err))
		return
	}

	for _, key := range user.Keys {
		if key.Fingerprint == fingerprint {
			ks.reply(nick, "Key already registered.")
			return
		}
	}

	user.Keys = append(user.Keys, SSHKey{
		Fingerprint: fingerprint,
		Key:         keyStr,
		Name:        keyName,
		Added:       time.Now(),
	})
	ks.saveDatabase()

	ks.reply(nick, fmt.Sprintf("✓ Added key: %s (%s)", fingerprint[:20]+"...", keyName))
	log.Printf("User %s added key: %s", nick, keyName)
}

func (ks *KeyServ) handleRemove(nick, fingerprint string) {
	user, exists := ks.db.Users[nick]
	if !exists || len(user.Keys) == 0 {
		ks.reply(nick, "No keys registered.")
		return
	}

	if len(user.Keys) == 1 {
		ks.reply(nick, "Can't remove your only key. Use 'add' to add another first.")
		return
	}

	for i, key := range user.Keys {
		if strings.HasPrefix(key.Fingerprint, fingerprint) || strings.Contains(key.Fingerprint, fingerprint) {
			user.Keys = append(user.Keys[:i], user.Keys[i+1:]...)
			ks.saveDatabase()
			ks.reply(nick, fmt.Sprintf("✓ Removed: %s (%s)", key.Fingerprint[:20]+"...", key.Name))
			log.Printf("User %s removed key: %s", nick, key.Name)
			return
		}
	}

	ks.reply(nick, "Key not found.")
}

func (ks *KeyServ) handleKeys(nick string) {
	user, exists := ks.db.Users[nick]
	if !exists || len(user.Keys) == 0 {
		ks.reply(nick, "No keys registered. Use 'auth' to get started.")
		return
	}

	ks.reply(nick, fmt.Sprintf("Your keys (%d):", len(user.Keys)))
	for i, key := range user.Keys {
		ks.reply(nick, fmt.Sprintf("  %d. %s... (%s) %s",
			i+1,
			key.Fingerprint[:20],
			key.Name,
			key.Added.Format("2006-01-02")))
	}
}

func (ks *KeyServ) handleWhoami(nick string) {
	user, exists := ks.db.Users[nick]

	if !exists {
		ks.reply(nick, "You are: "+nick+" (not registered)")
		return
	}

	authenticated := ks.isAuthenticated(nick)
	status := "not authenticated"
	if authenticated {
		status = "authenticated ✓"
	}

	ks.reply(nick, fmt.Sprintf("You are: %s (%s, %d keys)", nick, status, len(user.Keys)))
	if !user.LastSeen.IsZero() {
		ks.reply(nick, fmt.Sprintf("Last seen: %s", user.LastSeen.Format("2006-01-02 15:04")))
	}
}

func (ks *KeyServ) handleInfo(asker, nick string) {
	user, exists := ks.db.Users[nick]

	if !exists {
		ks.reply(asker, fmt.Sprintf("%s: Not registered", nick))
		return
	}

	authenticated := ks.isAuthenticated(nick)
	status := "offline/not authenticated"
	if authenticated {
		status = "online & authenticated ✓"
	}

	ks.reply(asker, fmt.Sprintf("%s: Registered (%d keys, %s)", nick, len(user.Keys), status))
	if !user.LastSeen.IsZero() {
		ks.reply(asker, fmt.Sprintf("Last seen: %s", user.LastSeen.Format("2006-01-02 15:04")))
	}
}

func (ks *KeyServ) sendHelp(nick string) {
	ks.reply(nick, fmt.Sprintf("=== KeyServ v%s - SSH Key Authentication ===", VERSION))
	ks.reply(nick, "Commands:")
	ks.reply(nick, "  auth [<ssh-key> [name]] - Register (new) or authenticate (existing)")
	ks.reply(nick, "  add <ssh-key> [name] - Add another key (requires auth)")
	ks.reply(nick, "  remove <fingerprint> - Remove a key (requires auth)")
	ks.reply(nick, "  keys - List your keys (requires auth)")
	ks.reply(nick, "  whoami - Check your authentication status")
	ks.reply(nick, "  info <nick> - Check if a nickname is registered")
	ks.reply(nick, "  version - Show bot version")
	ks.reply(nick, "Get your key: cat ~/.ssh/id_ed25519.pub")
}

func (ks *KeyServ) generateChallenge() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (ks *KeyServ) getKeyFingerprint(pubKey string) (string, error) {
	tmpFile, err := os.CreateTemp("", "ssh-key-*.pub")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(pubKey); err != nil {
		return "", err
	}
	tmpFile.Close()

	cmd := exec.Command("ssh-keygen", "-lf", tmpFile.Name())
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("invalid SSH key")
	}

	parts := strings.Fields(string(output))
	if len(parts) < 2 {
		return "", fmt.Errorf("could not parse fingerprint")
	}

	return parts[1], nil
}

func (ks *KeyServ) verifySignature(message, signature, publicKey string) bool {
	tmpDir, err := os.MkdirTemp("", "ssh-verify-*")
	if err != nil {
		log.Printf("Error creating temp dir: %v", err)
		return false
	}
	defer os.RemoveAll(tmpDir)

	msgFile := filepath.Join(tmpDir, "message.txt")
	if err := os.WriteFile(msgFile, []byte(message+"\n"), 0644); err != nil {
		log.Printf("Error writing message: %v", err)
		return false
	}

	sigFile := filepath.Join(tmpDir, "message.txt.sig")
	if err := os.WriteFile(sigFile, []byte(signature), 0644); err != nil {
		log.Printf("Error writing signature: %v", err)
		return false
	}

	allowedFile := filepath.Join(tmpDir, "allowed_signers")
	signerEntry := fmt.Sprintf("user %s\n", publicKey)
	if err := os.WriteFile(allowedFile, []byte(signerEntry), 0644); err != nil {
		log.Printf("Error writing allowed signers: %v", err)
		return false
	}

	cmd := exec.Command("ssh-keygen", "-Y", "verify",
		"-f", allowedFile,
		"-I", "user",
		"-n", ks.config.Bot.SignNamespace,
		"-s", sigFile)

	msgContent, _ := os.ReadFile(msgFile)
	cmd.Stdin = strings.NewReader(string(msgContent))

	output, err := cmd.CombinedOutput()

	if err == nil && strings.Contains(string(output), "Good") {
		return true
	}

	return false
}

func (ks *KeyServ) reply(nick, message string) {
	ks.ircConn.Privmsg(nick, message)
}

func (ks *KeyServ) loadDatabase() {
	ks.db = &Database{
		Users: make(map[string]*User),
	}

	data, err := os.ReadFile(ks.config.Bot.Database)
	if err != nil {
		if os.IsNotExist(err) {
			log.Println("Database not found, creating new")
			ks.saveDatabase()
			return
		}
		log.Fatalf("Error reading database: %v", err)
	}

	if err := json.Unmarshal(data, ks.db); err != nil {
		log.Fatalf("Error parsing database: %v", err)
	}

	log.Printf("Loaded %d users", len(ks.db.Users))
}

func (ks *KeyServ) saveDatabase() {
	data, err := json.MarshalIndent(ks.db, "", "  ")
	if err != nil {
		log.Printf("Error marshaling database: %v", err)
		return
	}

	if err := os.WriteFile(ks.config.Bot.Database, data, 0644); err != nil {
		log.Printf("Error saving database: %v", err)
	}
}
