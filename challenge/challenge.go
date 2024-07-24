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
    Token string 
    Timestamp time.Time  
} 

func NewChallengeSystem(challengePagePath string) *ChallengeSystem { 
    challengeTemplate, err := template.ParseFiles(challengePagePath)
    if err != nil { 
        logging.LogEvent("ERROR", fmt.Sprintf("Failed to load challenge template: %v", err))  
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
    challenge, challengeExists := cs.activeChallenges[clientIP] 
    cs.mutex.Unlock() 
    
    if challengeExists && time.Since(challenge.Timestamp) >= (2 * time.Second) && challenge.Token == r.FormValue("challengeToken") { 
        delete(cs.activeChallenges, clientIP) 
        logging.LogEvent("INFO", fmt.Sprintf("Challenge passed from: %s", clientIP))  
        return true
    } 

    newToken := generateSecureToken()
    
    cs.mutex.Lock() 
    for ip, chInfo := range cs.activeChallenges {
        if time.Since(chInfo.Timestamp) >= cs.challengeTimeout {
            delete(cs.activeChallenges, ip) 
        }
    }
    cs.activeChallenges[clientIP] = challengeInfo{ 
        Token: newToken,
        Timestamp: time.Now(),  
    } 
    cs.mutex.Unlock()
    
    data := struct { 
        Token string 
    }{ 
        Token: newToken,  
    } 
 
    if err := cs.challengePageTemplate.Execute(w, data); err != nil { 
        logging.LogEvent("ERROR", fmt.Sprintf("Error executing challenge template: %v", err))  
        http.Error(w, "Internal Server Error", http.StatusInternalServerError) 
        return false  
    }  

    return false 
}
 
func generateSecureToken() string {
    tokenBytes := make([]byte, 16) 
    _, err := rand.Read(tokenBytes)
    if err != nil {
        logging.LogEvent("ERROR", fmt.Sprintf("Error generating random token: %v", err))
        return ""
    }

    return hex.EncodeToString(tokenBytes)  
} 