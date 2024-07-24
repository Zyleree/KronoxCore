package routing

import (
	"fmt"
	"net"
	"sync" 

	"fortify/logging" 
) 

type BackendServer struct { 
	IP   string `json:"ip"`
	Port int    `json:"port"`
}  

var ( 
	routingTable = make(map[string]*BackendServer) 
	mutex sync.RWMutex 
)

func AddRoute(frontendIP string, frontendPort int, backendIP string, backendPort int) error {
	mutex.Lock()  
	defer mutex.Unlock() 
 
	frontendAddr := fmt.Sprintf("%s:%d", frontendIP, frontendPort)  

	if net.ParseIP(frontendIP) == nil {  
		logging.LogEvent("ERROR", fmt.Sprintf("Invalid frontend IP address: %s", frontendIP))
		return fmt.Errorf("invalid frontend IP address: %s", frontendIP) 
	}
	if net.ParseIP(backendIP) == nil {
		logging.LogEvent("ERROR", fmt.Sprintf("Invalid backend IP address: %s", backendIP))  
		return fmt.Errorf("invalid backend IP address: %s", backendIP)  
	}  
	
	routingTable[frontendAddr] = &BackendServer{IP: backendIP, Port: backendPort}  
	logging.LogEvent("INFO", fmt.Sprintf("Route added/updated: %s -> %s:%d", frontendAddr, backendIP, backendPort)) 
	return nil 
} 

func RemoveRoute(frontendIP string, frontendPort int) {  
	mutex.Lock() 
	defer mutex.Unlock() 

	frontendAddr := fmt.Sprintf("%s:%d", frontendIP, frontendPort) 
	delete(routingTable, frontendAddr)  
	logging.LogEvent("INFO", fmt.Sprintf("Route removed for: %s", frontendAddr))  
}

func GetBackendServer(frontendIP string, frontendPort int) (*BackendServer, error) {  
	mutex.RLock() 
	defer mutex.RUnlock() 
 
	frontendAddr := fmt.Sprintf("%s:%d", frontendIP, frontendPort)  
	backend, exists := routingTable[frontendAddr]
	if !exists {
		return nil, fmt.Errorf("no backend server found for address: %s", frontendAddr)  
	} 
	return backend, nil  
}