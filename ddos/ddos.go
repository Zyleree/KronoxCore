package ddos 

import (
	"net/http" 
	"sync" 
	"time"  
) 

type RateLimitConfig struct {
    RequestsPerSecond int `json:"requestsPerSecond"`  
}

type DDOSProtection struct { 
    rateLimitConfig *RateLimitConfig
    requestCounts map[string]int  
    mutex sync.Mutex
    lastReset time.Time
}  

func NewDDOSProtection(rateLimitConfig RateLimitConfig) (*DDOSProtection, error) {  
	return &DDOSProtection{
		rateLimitConfig: &rateLimitConfig, 
		requestCounts: make(map[string]int), 
		lastReset: time.Now(),  
	}, nil
}

func (dp *DDOSProtection) IsSuspicious(r *http.Request) bool {
	dp.mutex.Lock()
	defer dp.mutex.Unlock() 

	clientIP := r.RemoteAddr 
	dp.requestCounts[clientIP]++  
    
	if time.Since(dp.lastReset) >= time.Second {  
		dp.requestCounts = make(map[string]int) 
		dp.lastReset = time.Now()
	}  

	if dp.requestCounts[clientIP] > dp.rateLimitConfig.RequestsPerSecond {
		return true  
	} 

	return false  
}  