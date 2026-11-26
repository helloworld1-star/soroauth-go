package fixtures

import (
	"log"
)

// violating_logging.go violates no-logging
func ViolatingLogging() {
	log.Println("logging something")
}
