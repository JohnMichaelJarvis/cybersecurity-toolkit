package main

import (
    "fmt"
    "net"
    "time"
)

func main() {
    target := "scanme.nmap.org"
    for port := 20; port <= 1024; port++ {
        address := fmt.Sprintf("%s:%d", target, port)
        conn, err := net.DialTimeout("tcp", address, 1*time.Second)
        if err == nil {
            fmt.Printf("Port %d open\n", port)
            conn.Close()
        }
    }
}
