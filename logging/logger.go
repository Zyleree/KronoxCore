package logging 

import ( 
    "encoding/json"
	"fmt"
	"os"
	"sync" 
	"time" 
)

type LogLevel string

const ( 
    LogLevelInfo LogLevel = "INFO" 
    LogLevelWarning LogLevel = "WARNING" 
    LogLevelError LogLevel = "ERROR"  
)

type LogEntry struct {
	Timestamp string       `json:"timestamp"` 
	Level     LogLevel      `json:"level"` 
	Message   string       `json:"message"` 
	Request   *HTTPRequest  `json:"request,omitempty"` 
}
type HTTPRequest struct { 
    Method string `json:"method,omitempty"`  
	Host string `json:"host,omitempty"`
	URL   string  `json:"url,omitempty"` 
	From string  `json:"from,omitempty"`  
	Agent  string `json:"user_agent,omitempty"` 
}
var (
    logFile  *os.File  
    logMutex sync.Mutex 
)

func SetupLogger(logFilePath string) error {  
	if err := os.MkdirAll("logs", 0755); err != nil { // Creates 'logs' directory
		return fmt.Errorf("error creating log directory: %w", err)
	}

	var err error  
	logFile, err = os.OpenFile(logFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil { 
		return fmt.Errorf("error opening log file: %w", err)  
	}
	return nil  
} 
  
func LogEventCustom(logEntry LogEntry){ 
	logMutex.Lock() 
	defer logMutex.Unlock() 

	logEntry.Timestamp = time.Now().Format(time.RFC3339)

    jsonLog, err := json.Marshal(logEntry)
	if err != nil {  
		fmt.Fprintf(os.Stderr, "Error Marshalling JSON log:  %v\n", err) 
		return  
	}

    if _, err := logFile.Write(jsonLog); err != nil {  
		fmt.Fprintf(os.Stderr, "Error writing to log: %v\n", err) 
	}
}


func LogEvent(level string, r *http.Request,  message string) {  
	logMutex.Lock() 
	defer logMutex.Unlock()  
	timestamp := time.Now().Format(time.RFC3339) 
    var httpRequest *HTTPRequest
	if r != nil{  
		httpRequest = &HTTPRequest{
            Method: r.Method,  
			Host:   r.Host, 
            URL:    r.URL.String(),
			From:   r.RemoteAddr,  
            Agent:  r.UserAgent(),
		}
	}	

	logData := LogEntry{
		Timestamp: timestamp,
		Level:     LogLevel(level),  
		Message:   message,
		Request:    httpRequest, 
	}
	jsonLog, err := json.Marshal(logData)
    if err != nil {  
		fmt.Fprintf(os.Stderr, "Error Marshalling JSON log:  %v\n", err) 
		return  
	}

    if _, err := logFile.Write(jsonLog); err != nil {  
		fmt.Fprintf(os.Stderr, "Error writing to log: %v\n", err) 
	} 
}


func CloseLogFile() {  
	if logFile != nil {  
		if err := logFile.Close(); err != nil { 
			fmt.Fprintf(os.Stderr, "Error closing log file: %v\n", err) 
		} 
	}
} 

func GetLogFile() *os.File { 
	return logFile 
}