package challenge

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"

	"fortify/logging"
)

// ChallengeSystem ...
type ChallengeSystem struct {
	challengePageTemplate *template.Template
	activeChallenges     map[string]string
	mutex                 sync.Mutex
	challengeTimeout     time.Duration // Timeout for challenges
}

// NewChallengeSystem ...
func NewChallengeSystem(challengePagePath string) *ChallengeSystem {
	challengeTemplate, err := template.ParseFiles(challengePagePath)
	if err != nil {
		logging.LogEvent("ERROR", fmt.Sprintf("Failed to load challenge template: %v", err))
		return &ChallengeSystem{}
	}

	return &ChallengeSystem{
		challengePageTemplate: challengeTemplate,
		activeChallenges:     make(map[string]string),
		mutex:                 sync.Mutex{},
		challengeTimeout:     3 * time.Minute,
	}
}

// IsAllowed ...
func (cs *ChallengeSystem) IsAllowed(w http.ResponseWriter, r *http.Request) bool {
	clientIP := r.RemoteAddr

	cs.mutex.Lock()
	token, challengeExists := cs.activeChallenges[clientIP]
	challengeCreationTime := time.Now()
	cs.mutex.Unlock()

	if challengeExists && time.Since(challengeCreationTime) < cs.challengeTimeout && token == r.FormValue("challengeToken") {
		delete(cs.activeChallenges, clientIP) // Challenge passed
		return true
	}

	// Present a new challenge
	newToken := generateSecureToken()

	cs.mutex.Lock()
	cs.activeChallenges[clientIP] = newToken
	cs.mutex.Unlock()

	data := struct {
		Token string
	}{
		Token: newToken,
	}

	if err := cs.challengePageTemplate.Execute(w, data); err != nil {
		logging.LogEvent("ERROR", fmt.Sprintf("Error executing challenge template: %v", err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return false
	}

	return false
}

// generateSecureToken ...
func generateSecureToken() string {
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		logging.LogEvent("ERROR", fmt.Sprintf("Error generating random token: %v", err))
		return ""
	}
	return hex.EncodeToString(tokenBytes)
}