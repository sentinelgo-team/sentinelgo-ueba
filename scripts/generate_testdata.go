//go:build ignore

package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"
)

func main() {
	sizes := map[string]int{
		"testdata/medium_auth.log": 1000,
		"testdata/large_auth.log":  10000,
	}

	users := []string{"admin", "root", "user1", "user2", "deploy", "svc_backup",
		"postgres", "attacker", "hacker", "operator", "developer"}
	hosts := []string{"web01", "web02", "db01", "db02", "app01", "app02",
		"jump01", "monitor", "backup01", "ci-server"}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for filename, count := range sizes {
		file, err := os.Create(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating %s: %v\n", filename, err)
			continue
		}

		baseTime := time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC)
		for i := 0; i < count; i++ {
			ts := baseTime.Add(time.Duration(i*2) * time.Second)
			user := users[rng.Intn(len(users))]
			host := hosts[rng.Intn(len(hosts))]

			var message string
			switch rng.Intn(4) {
			case 0:
				message = fmt.Sprintf("Failed password for %s from 192.168.%d.%d port %d ssh2",
					user, rng.Intn(256), rng.Intn(256), 20000+rng.Intn(40000))
			case 1:
				message = fmt.Sprintf("Accepted password for %s from 10.%d.%d.%d port %d ssh2",
					user, rng.Intn(256), rng.Intn(256), rng.Intn(256), 20000+rng.Intn(40000))
			case 2:
				message = fmt.Sprintf("Failed password for invalid user %s from 172.16.%d.%d port %d ssh2",
					user, rng.Intn(256), rng.Intn(256), 20000+rng.Intn(40000))
			default:
				message = fmt.Sprintf("Failed password for %s from 192.168.%d.%d port %d ssh2",
					user, rng.Intn(256), rng.Intn(256), 20000+rng.Intn(40000))
			}

			line := fmt.Sprintf("%s %s sshd[%d]: %s\n",
				ts.Format("Jan  2 15:04:05"), host, 1000+rng.Intn(9000), message)
			file.WriteString(line)
		}

		file.Close()
		fmt.Printf("Generated %s (%d events)\n", filename, count)
	}
}
