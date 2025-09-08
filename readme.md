# parkchat-server

A simple, room-based real-time chat server built with Go. It uses WebSockets for communication, SQLite for data persistence, and provides basic user authentication.

-----

## Features ✨

  * **User Registration:** Secure user registration with password hashing (bcrypt).
  * **Multiple Chat Rooms:** Create and join different chat rooms dynamically based on the URL path.
  * **Real-Time Messaging:** Instant message broadcasting to all users in a specific room using WebSockets.
  * **Message History:** An endpoint to retrieve the last 50 messages from a chat room.
  * **System Messages:** Automatic notifications when a user joins or leaves a room.
  * **Persistent Storage:** Chat messages and user data are saved in a local SQLite database (`chat.db`).

-----

## Tech Stack 🛠️

  * **Backend:** Go
  * **WebSocket:** `gorilla/websocket`
  * **Database:** SQLite (using `glebarez/sqlite` driver)
  * **Password Hashing:** `golang.org/x/crypto/bcrypt`

-----

## Getting Started

Follow these instructions to get the server up and running on your local machine.

### Prerequisites

  * Go (version 1.18 or newer is recommended)

### Installation & Running

1.  **Clone the repository:**

    ```sh
    git clone <your-repository-url>
    cd <repository-folder>
    ```

2.  **Install dependencies:**
    This project uses Go Modules. Dependencies will be downloaded automatically on the first run, or you can fetch them manually.

    ```sh
    go mod tidy
    ```

3.  **Run the server:**

    ```sh
    go run ./server/main.go
    ```

    The server will start on port `8080` by default and will create a `chat.db` file in the project root to store data.

-----

## API Endpoints & Usage 📖

### 1\. Register a User

  * **Endpoint:** `POST /register`
  * **Description:** Creates a new user account.
  * **Request Body (JSON):**
    ```json
    {
        "nickname": "your_nickname",
        "password": "your_password"
    }
    ```
  * **Responses:**
      * `201 Created`: If the user is successfully registered.
      * `409 Conflict`: If the nickname already exists.
      * `400 Bad Request`: If the nickname or password is empty.

### 2\. Get Chat History

  * **Endpoint:** `GET /history/{roomName}`
  * **Description:** Retrieves the last 50 messages from the specified chat room.
  * **Authentication:** **HTTP Basic Auth**. Use the nickname and password of a registered user.
  * **Response:**
      * `200 OK`: Returns a JSON array of message objects.
        ```json
        [
            {
                "id": 0,
                "chat_room": "",
                "nickname": "user1",
                "content": "Hello World!",
                "timestamp": "2025-09-08T15:30:00Z"
            }
        ]
        ```
      * `401 Unauthorized`: If authentication fails.

### 3\. Connect to Chat (WebSocket)

  * **Endpoint:** `GET /ws/{roomName}`
  * **Description:** Upgrades the HTTP connection to a WebSocket to join a chat room.
  * **Authentication:** **HTTP Basic Auth**. Use the nickname and password of a registered user.
  * **URL Example:** `ws://localhost:8080/ws/general`

#### **WebSocket Communication**

  * **Sending Messages:** Send a JSON object with a `content` key. The server will automatically fill in the other details (nickname, timestamp, etc.).

    ```json
    {
        "content": "This is my message!"
    }
    ```

  * **Receiving Messages:** You will receive message objects in the following format. The `type` can be `"chat"` for user messages or `"system"` for join/leave notifications.

    ```json
    {
        "id": 123,
        "chat_room": "general",
        "nickname": "some_user",
        "content": "Hello everyone!",
        "timestamp": "2025-09-08T15:32:10Z",
        "type": "chat"
    }
    ```

    ```json
    {
        "id": 0,
        "chat_room": "general",
        "nickname": "some_user",
        "content": "some_user has joined the room",
        "timestamp": "2025-09-08T15:31:05Z",
        "type": "system"
    }
    ```

### 4\. Health Check

  * **Endpoint:** `GET /health`
  * **Description:** A simple endpoint to check if the server is running.
  * **Response:**
      * `200 OK`: With a plain text body `OK`.