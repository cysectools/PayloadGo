package main

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func main() {
	fmt.Println("PayloadGo Simple Example")
	fmt.Println("========================")

	// Simple HTTP request example
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Test URL with a simple payload
	testURL := "http://httpbin.org/get?test=<script>alert(1)</script>"

	fmt.Printf("Testing URL: %s\n", testURL)

	resp, err := client.Get(testURL)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		return
	}

	fmt.Printf("Status Code: %d\n", resp.StatusCode)
	fmt.Printf("Response Length: %d bytes\n", len(body))

	// Check if payload is reflected
	if string(body) != "" {
		fmt.Println("Response received successfully!")
	}
}
