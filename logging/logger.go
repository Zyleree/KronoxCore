package logging

import (
	"fmt"
	"os"
	"sync"
	"time"
)

var (
	logFile *os.File
	logMutex sync.Mutex
)

// SetupLogger ...
func SetupLogger(logFilePath string) error {
	if err := os.MkdirAll("logs", 0755); err != nil {
		return fmt.Errorf("error creating log directory: %w", err)
	}

	var err error
	logFile, err = os.OpenFile(logFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("error opening log file: %w", err)
	}
	return nil
}

// LogEvent ...
func LogEvent(level, message string) {
	logMutex.Lock()
	defer logMutex.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logMessage := fmt.Sprintf("[%s] [%s] %s\n", timestamp, level, message)
	if _, err := logFile.WriteString(logMessage); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to log file: %v\n", err)
	}
}

// CloseLogFile ...
func CloseLogFile() {
	if logFile != nil {
		if err := logFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing log file: %v\n", err)
		}
	}
}