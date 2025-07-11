package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"io/ioutil"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v5"
)

var (
	AppVersion    = "0.1.0-dev"
	BuildDateTime = "2025-07-10T13:00:00Z"
)

type BuildInfo struct {
	Version        string `json:"version"`
	BuildDateTime  string `json:"buildDateTime"`
	BuildTimestamp int64  `json:"buildTimestamp"`
	Environment    string `json:"environment"`
	Service        string `json:"service"`
	Description    string `json:"description"`
}

type VersionResponse struct {
	Version   string     `json:"version"`
	BuildInfo *BuildInfo `json:"buildInfo,omitempty"`
	Error     string     `json:"error"`
}

func loadBuildInfo() *BuildInfo {
	data, err := ioutil.ReadFile("/app/build-info.json")
	if err != nil {
		return nil
	}
	var buildInfo BuildInfo
	if err := json.Unmarshal(data, &buildInfo); err != nil {
		return nil
	}
	return &buildInfo
}

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

// User struct for DB
type User struct {
	ID         int
	Username   string
	Password   string
	Role       string
	Permissions string // comma-separated
}

type Claims struct {
	UserID      int      `json:"user_id"`
	Username    string   `json:"username"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	jwt.RegisteredClaims
}

func initDB(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		role TEXT NOT NULL,
		permissions TEXT NOT NULL DEFAULT ''
	);`)
	if err != nil {
		return err
	}
	// Check if users exist
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		adminPass, err := bcrypt.GenerateFromPassword([]byte("brickadminpass"), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		userPass, err := bcrypt.GenerateFromPassword([]byte("brickpass"), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		// Admin: all permissions
		_, err = db.Exec(`INSERT INTO users (username, password, role, permissions) VALUES (?, ?, ?, ?)`,
			"brick-admin", string(adminPass), "admin", "edit_users,view_logs,delete_users,view_profile")
		if err != nil {
			return err
		}
		// Common user: limited permissions
		_, err = db.Exec(`INSERT INTO users (username, password, role, permissions) VALUES (?, ?, ?, ?)`,
			"brick", string(userPass), "user", "view_profile")
		if err != nil {
			return err
		}
		log.Println("Initialized DB with default users: brick-admin/brick and their roles/permissions")
	}
	return nil
}

func main() {
	os.MkdirAll("/app/data", 0755)
	db, err := sql.Open("sqlite3", "/app/data/users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := initDB(db); err != nil {
		log.Fatalf("DB init error: %v", err)
	}

	// Load RSA private key
	privPem, err := ioutil.ReadFile("/app/private.pem")
	if err != nil {
		log.Fatalf("Failed to read private.pem: %v", err)
	}
	block, _ := pem.Decode(privPem)
	if block == nil {
		log.Fatalf("Failed to decode PEM block containing private key")
	}
	var parsedKey interface{}
	if block.Type == "RSA PRIVATE KEY" {
		parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "PRIVATE KEY" {
		parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	} else {
		log.Fatalf("Unknown key type %s", block.Type)
	}
	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok || err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}
	publicKey = &privateKey.PublicKey

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
			return
		}
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
			return
		}
		var user User
		err := db.QueryRow("SELECT id, username, password, role, permissions FROM users WHERE username = ?", creds.Username).Scan(&user.ID, &user.Username, &user.Password, &user.Role, &user.Permissions)
		if err != nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)) != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
			return
		}
		permissions := []string{}
		if user.Permissions != "" {
			permissions = strings.Split(user.Permissions, ",")
		}
		expirationTime := time.Now().Add(15 * time.Minute)
		claims := &Claims{
			UserID:   user.ID,
			Username: user.Username,
			Role:     user.Role,
			Permissions: permissions,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expirationTime),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, err := token.SignedString(privateKey)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Could not create token"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"token": tokenString})
	})

	http.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		tokenStr := getBearerToken(r)
		if tokenStr == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Missing token"})
			return
		}
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil || !token.Valid {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"valid": true, "user": claims})
	})

	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		tokenStr := getBearerToken(r)
		if tokenStr == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Missing token"})
			return
		}
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil || !token.Valid {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
			return
		}
		expirationTime := time.Now().Add(15 * time.Minute)
		claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(expirationTime)
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, err := token.SignedString(privateKey)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Could not refresh token"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"token": tokenString})
	})

	http.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		tokenStr := getBearerToken(r)
		if tokenStr == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Missing token"})
			return
		}
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil || !token.Valid {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"user": claims})
	})

	http.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
			return
		}
		version := AppVersion
		buildInfo := loadBuildInfo()
		resp := VersionResponse{
			Version:   version,
			BuildInfo: buildInfo,
			Error:     "",
		}
		writeJSON(w, http.StatusOK, resp)
	})

	log.Println("Starting brick-auth on :17001...")
	log.Fatal(http.ListenAndServe(":17001", nil))
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func getBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
} 