package ddos

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type RateLimitConfig struct {
	RequestsPerSecond int `json:"requestsPerSecond"`
	Burst             int `json:"burst"` 
}

type DDOSProtection struct {
	rateLimitConfig *RateLimitConfig
	limiters     map[string]*rate.Limiter 
	mutex         sync.Mutex             
	lastReset     time.Time
}

func NewDDOSProtection(rateLimitConfig RateLimitConfig) (*DDOSProtection, error) {
	return &DDOSProtection{
		rateLimitConfig: &rateLimitConfig,
		limiters:     make(map[string]*rate.Limiter), // Initilize the limiter
		lastReset:     time.Now(),
	}, nil
}

func (dp *DDOSProtection) IsSuspicious(r *http.Request) bool {
	dp.mutex.Lock()
	defer dp.mutex.Unlock()

	clientIP := r.RemoteAddr

	limiter, ok := dp.limiters[clientIP]
	if !ok {
		limiter = rate.NewLimiter(rate.Every(time.Second/time.Duration(dp.rateLimitConfig.RequestsPerSecond)), dp.rateLimitConfig.Burst)
		dp.limiters[clientIP] = limiter
	}
	if !limiter.Allow() {
		return true 
	}
	return false
}