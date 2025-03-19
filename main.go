package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const (
	APIKEY     = "private KEY" // put your key
	BACKENDURL = "http://example.com" // put your backend to send url
)

type IPReport struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		IPcountry            string `json:"countryCode"`
		IPIsp                string `json:"isp"`
		IPDomain             string `json:"domain"`
	} `json:"data"`
}

func extractIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = r.RemoteAddr
	}
	if strings.Contains(ip, ":") {
		ip = strings.Split(ip, ":")[0]
	}
	return ip
}

func checkIP(ip string) bool {
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s", ip)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Key", APIKEY)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var report IPReport
	if err := json.Unmarshal(body, &report); err != nil {
		return false
	}
	return report.Data.AbuseConfidenceScore <= 50
}

func reverseProxy(target string) *httputil.ReverseProxy {
	url, _ := url.Parse(target)
	return httputil.NewSingleHostReverseProxy(url)
}

func handler(w http.ResponseWriter, r *http.Request) {
	ip := extractIP(r)
	if !checkIP(ip) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}
	proxy := reverseProxy(BACKENDURL)
	proxy.ServeHTTP(w, r)
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Reverse proxy in esecuzione su http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
