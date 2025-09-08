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

// --- Struktury danych ---

// User reprezentuje użytkownika w systemie
type User struct {
	ID           int
	Nickname     string `json:"nickname"`
	PasswordHash string `json:"-"` // Pomijamy w JSON
}

// Credentials służy do odczytywania danych logowania/rejestracji z requestu
type Credentials struct {
	Nickname string `json:"nickname"`
	Password string `json:"password"`
}

// Message reprezentuje pojedynczą wiadomość w czacie
type Message struct {
	ID        int       `json:"id"`
	ChatRoom  string    `json:"chat_room"`
	Nickname  string    `json:"nickname"`
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"` // "chat" albo "system"
}

// --- WebSocketowe struktury i globalne zmienne ---

var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		// Dopuszczamy połączenia z dowolnego źródła. W produkcyjnym środowisku należy to ograniczyć!
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	// chats przechowuje aktywne połączenia dla każdego pokoju czatu
	// Format: map[pokoj_czatu]map[*websocket.Conn]bool
	chats = make(map[string]map[*websocket.Conn]bool)
	// Mutex do zabezpieczenia dostępu do mapy `chats`
	mu sync.Mutex
)

// --- Logika bazy danych ---

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "./chat.db")
	if err != nil {
		log.Fatal("Błąd połączenia z bazą danych:", err)
	}

	// Tabela użytkowników
	usersTable := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nickname TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL
    );`
	_, err = db.Exec(usersTable)
	if err != nil {
		log.Fatal("Błąd tworzenia tabeli users:", err)
	}

	// Tabela wiadomości
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
		log.Fatal("Błąd tworzenia tabeli messages:", err)
	}

	log.Println("Baza danych SQLite zainicjowana pomyślnie.")
}

// --- Funkcje pomocnicze związane z użytkownikami ---

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

// --- Handlery HTTP ---

func handleHistory(w http.ResponseWriter, r *http.Request) {
	nickname, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "Brak danych autoryzacyjnych", http.StatusUnauthorized)
		return
	}

	user, err := getUserByNickname(nickname)
	if err != nil || !checkPasswordHash(password, user.PasswordHash) {
		http.Error(w, "Nieprawidłowy nick lub hasło", http.StatusUnauthorized)
		return
	}

	roomName := strings.TrimPrefix(r.URL.Path, "/history/")
	if roomName == "" {
		http.Error(w, "Nie podano nazwy pokoju czatu", http.StatusBadRequest)
		return
	}

	rows, err := db.Query("SELECT nickname, content, timestamp FROM messages WHERE chat_room = ? ORDER BY timestamp ASC LIMIT 50", roomName)
	if err != nil {
		http.Error(w, "Błąd pobierania historii wiadomości", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var msg Message
		if err := rows.Scan(&msg.Nickname, &msg.Content, &msg.Timestamp); err != nil {
			http.Error(w, "Błąd odczytu wiadomości", http.StatusInternalServerError)
			return
		}
		messages = append(messages, msg)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(messages)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Niedozwolona metoda", http.StatusMethodNotAllowed)
		return
	}
	log.Println("Odebrano POST /register")

	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Nieprawidłowy format danych", http.StatusBadRequest)
		return
	}

	if creds.Nickname == "" || creds.Password == "" {
		http.Error(w, "Nick i hasło nie mogą być puste", http.StatusBadRequest)
		return
	}

	passwordHash, err := hashPassword(creds.Password)
	if err != nil {
		http.Error(w, "Błąd serwera podczas hashowania hasła", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (nickname, password_hash) VALUES (?, ?)", creds.Nickname, passwordHash)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			http.Error(w, "Użytkownik o tym nicku już istnieje", http.StatusConflict)
		} else {
			http.Error(w, "Błąd serwera podczas tworzenia użytkownika", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Użytkownik %s został pomyślnie zarejestrowany.", creds.Nickname)
}

// --- WebSocket Handlery ---

// handleWebsocket odpowiada za obsługę połączeń WebSocket
// handleWebsocket odpowiada za obsługę połączeń WebSocket
func handleWebsocket(w http.ResponseWriter, r *http.Request) {
	nickname, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "Brak danych autoryzacyjnych", http.StatusUnauthorized)
		return
	}

	user, err := getUserByNickname(nickname)
	if err != nil || !checkPasswordHash(password, user.PasswordHash) {
		http.Error(w, "Nieprawidłowy nick lub hasło", http.StatusUnauthorized)
		return
	}

	roomName := strings.TrimPrefix(r.URL.Path, "/ws/")
	if roomName == "" {
		http.Error(w, "Nie podano nazwy pokoju czatu", http.StatusBadRequest)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Błąd uaktualniania do WebSocket:", err)
		return
	}
	log.Printf("Nowe połączenie WebSocket z użytkownikiem %s w pokoju '%s'\n", nickname, roomName)

	mu.Lock()
	if chats[roomName] == nil {
		chats[roomName] = make(map[*websocket.Conn]bool)
	}
	chats[roomName][conn] = true
	mu.Unlock()

	// broadcast wejścia
	joinMsg := Message{
		ChatRoom:  roomName,
		Nickname:  user.Nickname,
		Content:   fmt.Sprintf("%s dołączył do pokoju", user.Nickname),
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
		log.Printf("Użytkownik %s rozłączony z pokoju '%s'\n", nickname, roomName)

		// broadcast wyjścia
		leaveMsg := Message{
			ChatRoom:  roomName,
			Nickname:  user.Nickname,
			Content:   fmt.Sprintf("%s opuścił pokój", user.Nickname),
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
			log.Println("Błąd odczytu wiadomości:", err)
			break
		}

		msg.ChatRoom = roomName
		msg.Nickname = user.Nickname
		msg.Timestamp = time.Now()
		msg.Type = "chat"

		// zapisujemy tylko normalne wiadomości
		_, err = db.Exec("INSERT INTO messages (chat_room, user_id, nickname, content) VALUES (?, ?, ?, ?)",
			msg.ChatRoom, user.ID, msg.Nickname, msg.Content)
		if err != nil {
			log.Println("Błąd zapisu wiadomości do bazy:", err)
			continue
		}

		// Broadcast (rozsyłanie) wiadomości do wszystkich klientów w pokoju
		broadcastMessage(roomName, msg, conn)
	}
}

// broadcastMessage wysyła wiadomość do wszystkich aktywnych połączeń w danym pokoju
// z wyjątkiem nadawcy (sender)
func broadcastMessage(roomName string, msg Message, sender *websocket.Conn) {
	mu.Lock()
	defer mu.Unlock()

	if clients, ok := chats[roomName]; ok {
		for client := range clients {
			err := client.WriteJSON(msg)
			if err != nil {
				log.Println("Błąd wysyłania wiadomości do klienta:", err)
			}
		}
	}
}

// --- Funkcja główna ---

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
	log.Printf("Serwer czatu uruchomiony na porcie %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
