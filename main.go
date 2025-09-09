// server/main.go
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	_ "github.com/glebarez/sqlite"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// --- Data Structures ---

// User represents a user in the system.
type User struct {
	ID           int
	Nickname     string `json:"nickname"`
	PasswordHash string `json:"-"` // Omitted in JSON
}

// Credentials is used to read login/registration data from the request.
type Credentials struct {
	Nickname string `json:"nickname"`
	Password string `json:"password"`
}

// Message represents a single chat message.
type Message struct {
	ID        int       `json:"id"`
	ChatRoom  string    `json:"chat_room"`
	Nickname  string    `json:"nickname"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"` // "chat" or "system"
}

// --- WebSocket Structures and Global Variables ---

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		// We allow connections from any origin. In a production environment, this should be restricted!
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	// chats stores active connections for each chat room.
	// Format: map[chat_room]map[*websocket.Conn]bool
	chats = make(map[string]map[*websocket.Conn]bool)
	// Mutex to protect access to the `chats` map.
	mu sync.Mutex
)

// --- Database Logic ---

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "./chat.db")
	if err != nil {
		log.Fatal("Error connecting to the database:", err)
	}

	// Users table
	usersTable := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nickname TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL
    );`
	_, err = db.Exec(usersTable)
	if err != nil {
		log.Fatal("Error creating users table:", err)
	}

	// Messages table
	messagesTable := `
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_room TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        nickname TEXT NOT NULL,
        content TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );`
	_, err = db.Exec(messagesTable)
	if err != nil {
		log.Fatal("Error creating messages table:", err)
	}

	log.Println("SQLite database initialized successfully.")
}

// --- User-related Helper Functions ---

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func getUserByNickname(nickname string) (*User, error) {
	user := &User{}
	err := db.QueryRow("SELECT id, nickname, password_hash FROM users WHERE nickname = ?", nickname).Scan(&user.ID, &user.Nickname, &user.PasswordHash)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// --- HTTP Handlers ---

func handleHistory(w http.ResponseWriter, r *http.Request) {
	nickname, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "Authorization data missing", http.StatusUnauthorized)
		return
	}

	user, err := getUserByNickname(nickname)
	if err != nil || !checkPasswordHash(password, user.PasswordHash) {
		http.Error(w, "Invalid nickname or password", http.StatusUnauthorized)
		return
	}

	roomName := strings.TrimPrefix(r.URL.Path, "/history/")
	if roomName == "" {
		http.Error(w, "Chat room name not provided", http.StatusBadRequest)
		return
	}

	rows, err := db.Query("SELECT nickname, content, timestamp FROM messages WHERE chat_room = ? ORDER BY timestamp DESC LIMIT 50", roomName)
	if err != nil {
		http.Error(w, "Error fetching message history", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []Message
	var temp []Message
	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.Nickname, &msg.Content, &msg.Timestamp); err != nil {
			http.Error(w, "Error reading message", http.StatusInternalServerError)
			return
		}
		temp = append(temp, msg)
	}

	for i := len(temp) - 1; i >= 0; i-- {
		messages = append(messages, temp[i])
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	log.Println("Received POST /register")

	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid data format", http.StatusBadRequest)
		return
	}

	if creds.Nickname == "" || creds.Password == "" {
		http.Error(w, "Nickname and password cannot be empty", http.StatusBadRequest)
		return
	}

	passwordHash, err := hashPassword(creds.Password)
	if err != nil {
		http.Error(w, "Server error while hashing password", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (nickname, password_hash) VALUES (?, ?)", creds.Nickname, passwordHash)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			http.Error(w, "User with this nickname already exists", http.StatusConflict)
		} else {
			http.Error(w, "Server error while creating user", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "User %s has been successfully registered.", creds.Nickname)
}

// --- WebSocket Handlers ---

// handleWebsocket is responsible for handling WebSocket connections.
func handleWebsocket(w http.ResponseWriter, r *http.Request) {
	nickname, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "Authorization data missing", http.StatusUnauthorized)
		return
	}

	user, err := getUserByNickname(nickname)
	if err != nil || !checkPasswordHash(password, user.PasswordHash) {
		http.Error(w, "Invalid nickname or password", http.StatusUnauthorized)
		return
	}

	roomName := strings.TrimPrefix(r.URL.Path, "/ws/")
	if roomName == "" {
		http.Error(w, "Chat room name not provided", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error upgrading to WebSocket:", err)
		return
	}
	log.Printf("New WebSocket connection from user %s in room '%s'\n", nickname, roomName)

	mu.Lock()
	if chats[roomName] == nil {
		chats[roomName] = make(map[*websocket.Conn]bool)
	}
	chats[roomName][conn] = true
	mu.Unlock()

	// Broadcast entry message
	joinMsg := Message{
		ChatRoom:  roomName,
		Nickname:  user.Nickname,
		Content:   fmt.Sprintf("%s has joined the room", user.Nickname),
		Timestamp: time.Now(),
		Type:      "system",
	}
	broadcastMessage(roomName, joinMsg, nil)

	defer func() {
		mu.Lock()
		delete(chats[roomName], conn)
		if len(chats[roomName]) == 0 {
			delete(chats, roomName)
		}
		mu.Unlock()
		conn.Close()
		log.Printf("User %s disconnected from room '%s'\n", nickname, roomName)

		// Broadcast exit message
		leaveMsg := Message{
			ChatRoom:  roomName,
			Nickname:  user.Nickname,
			Content:   fmt.Sprintf("%s has left the room", user.Nickname),
			Timestamp: time.Now(),
			Type:      "system",
		}
		broadcastMessage(roomName, leaveMsg, nil)
	}()

	for {
		var msg Message
		err := conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				break
			}
			log.Println("Error reading message:", err)
			break
		}

		msg.ChatRoom = roomName
		msg.Nickname = user.Nickname
		msg.Timestamp = time.Now()
		msg.Type = "chat"

		// We only save normal chat messages
		_, err = db.Exec("INSERT INTO messages (chat_room, user_id, nickname, content) VALUES (?, ?, ?, ?)",
			msg.ChatRoom, user.ID, msg.Nickname, msg.Content)
		if err != nil {
			log.Println("Error saving message to the database:", err)
			continue
		}

		// Broadcast the message to all clients in the room
		broadcastMessage(roomName, msg, conn)
	}
}

// broadcastMessage sends a message to all active connections in a given room,
// excluding the sender.
func broadcastMessage(roomName string, msg Message, sender *websocket.Conn) {
	mu.Lock()
	defer mu.Unlock()

	if clients, ok := chats[roomName]; ok {
		for client := range clients {
			err := client.WriteJSON(msg)
			if err != nil {
				log.Println("Error sending message to client:", err)
			}
		}
	}
}

// --- Main Function ---

func main() {
	initDB()
	defer db.Close()

	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/history/", handleHistory)
	http.HandleFunc("/ws/", handleWebsocket)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	})

	port := "8080"
	log.Printf("Chat server started on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
