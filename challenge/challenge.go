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

type ChallengeSystem struct {
	challengePageTemplate *template.Template
	activeChallenges     map[string]challengeInfo
	mutex                 sync.Mutex
	challengeTimeout     time.Duration
}

type challengeInfo struct {
	Token     string
	Timestamp time.Time
}

func NewChallengeSystem(challengePagePath string) *ChallengeSystem {
	challengeTemplate, err := template.ParseFiles(challengePagePath)
	if err != nil {
		logging.LogEvent("ERROR", nil, fmt.Sprintf("Failed to load challenge template: %v", err))
		return &ChallengeSystem{} 
	}
	return &ChallengeSystem{
		challengePageTemplate: challengeTemplate,
		activeChallenges:     make(map[string]challengeInfo),
		mutex:                 sync.Mutex{},
		challengeTimeout:     3 * time.Minute, 
	}
}

func (cs *ChallengeSystem) IsAllowed(w http.ResponseWriter, r *http.Request) bool {
	clientIP := r.RemoteAddr


	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	challenge, challengeExists := cs.activeChallenges[clientIP]


	if challengeExists && time.Since(challenge.Timestamp) >= cs.challengeTimeout {
		delete(cs.activeChallenges, clientIP)
		challengeExists = false
		logging.LogEvent("INFO", r, fmt.Sprintf("Challenge expired for IP:  %s", clientIP)) 
	}

	if challengeExists && time.Since(challenge.Timestamp) >= (2*time.Second) && challenge.Token == r.FormValue("challengeToken") {
		delete(cs.activeChallenges, clientIP)
		logging.LogEvent("INFO", r, fmt.Sprintf("Challenge PASSED by %s", r.RemoteAddr)) 
		return true 
	}
	
	newToken := generateSecureToken()

	cs.activeChallenges[clientIP] = challengeInfo{
		Token:     newToken,
		Timestamp: time.Now(),
	}

	data := struct {
		Token string
	}{
		Token: newToken,
	}

	if err := cs.challengePageTemplate.Execute(w, data); err != nil {
		logging.LogEvent("ERROR", r, fmt.Sprintf("Failed to execute challenge template: %v", err))  
		http.Error(w, "Internal server error", http.StatusInternalServerError) 
		return false 
	}
	logging.LogEvent("INFO", r, fmt.Sprintf("New challenge presented to %s", r.RemoteAddr))
}

func generateSecureToken() string {
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		logging.LogEvent("ERROR", nil, fmt.Sprintf("Error generating random token: %v", err))
		return "" 
	}
	return hex.EncodeToString(tokenBytes)
}