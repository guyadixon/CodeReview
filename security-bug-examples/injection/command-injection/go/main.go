package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

var logDir = "/var/log/sysadmin"
var uploadDir = "/tmp/uploads"

func pingHost(c *gin.Context) {
	host := c.Query("host")
	if host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host parameter is required"})
		return
	}

	cmd := exec.Command("sh", "-c", "ping -c 3 "+host)
	output, err := cmd.CombinedOutput()
	if err != nil && len(output) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"host": host, "output": string(output)})
}

func dnsLookup(c *gin.Context) {
	domain := c.Query("domain")
	recordType := c.DefaultQuery("type", "A")

	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain parameter is required"})
		return
	}

	allowedTypes := map[string]bool{
		"A": true, "AAAA": true, "MX": true,
		"NS": true, "TXT": true, "CNAME": true, "SOA": true,
	}
	if !allowedTypes[recordType] {
		recordType = "A"
	}

	result := runDig(domain, recordType)
	c.JSON(http.StatusOK, gin.H{"domain": domain, "type": recordType, "result": result})
}

func runDig(domain, recordType string) string {
	cmd := fmt.Sprintf("dig %s %s +short", recordType, domain)
	out, err := exec.Command("sh", "-c", cmd).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func searchLogs(c *gin.Context) {
	keyword := c.Query("keyword")
	logFile := c.DefaultQuery("file", "syslog")
	lines := c.DefaultQuery("lines", "100")

	if keyword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "keyword parameter is required"})
		return
	}

	logPath := filepath.Join(logDir, logFile)
	cmd := fmt.Sprintf("tail -n %s %s | grep '%s'", lines, logPath, keyword)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil && len(out) == 0 {
		c.JSON(http.StatusOK, gin.H{"file": logFile, "matches": []string{}})
		return
	}

	matches := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(matches) == 1 && matches[0] == "" {
		matches = []string{}
	}
	c.JSON(http.StatusOK, gin.H{"file": logFile, "matches": matches})
}

func listFiles(c *gin.Context) {
	directory := c.DefaultQuery("path", uploadDir)
	pattern := c.DefaultQuery("pattern", "*")

	cmd := exec.Command("find", directory, "-name", pattern, "-maxdepth", "2")
	out, err := cmd.Output()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	files := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(files) == 1 && files[0] == "" {
		files = []string{}
	}
	c.JSON(http.StatusOK, gin.H{"directory": directory, "files": files})
}

func archiveFiles(c *gin.Context) {
	var req struct {
		Path string `json:"path" binding:"required"`
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path is required"})
		return
	}

	archiveName := req.Name
	if archiveName == "" {
		archiveName = "archive"
	}
	archiveName = strings.ReplaceAll(archiveName, "/", "_")
	archiveName = strings.ReplaceAll(archiveName, "\\", "_")

	archivePath := fmt.Sprintf("/tmp/%s.tar.gz", archiveName)
	cmd := fmt.Sprintf("tar czf %s %s", archivePath, req.Path)
	_, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"archive": archivePath})
}

func checkPort(c *gin.Context) {
	var req struct {
		Host string `json:"host" binding:"required"`
		Port int    `json:"port" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "host and port are required"})
		return
	}

	if req.Port < 1 || req.Port > 65535 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid port range"})
		return
	}

	cmd := fmt.Sprintf("nc -zv -w 3 %s %d", req.Host, req.Port)
	out, _ := exec.Command("sh", "-c", cmd).CombinedOutput()
	c.JSON(http.StatusOK, gin.H{
		"host": req.Host, "port": req.Port, "result": string(out),
	})
}

func systemInfo(c *gin.Context) {
	hostname, _ := exec.Command("hostname").Output()
	uptime, _ := exec.Command("uptime", "-p").Output()
	kernel, _ := exec.Command("uname", "-r").Output()
	disk, _ := exec.Command("df", "-h", "/").Output()

	c.JSON(http.StatusOK, gin.H{
		"hostname": strings.TrimSpace(string(hostname)),
		"uptime":   strings.TrimSpace(string(uptime)),
		"kernel":   strings.TrimSpace(string(kernel)),
		"disk":     strings.TrimSpace(string(disk)),
	})
}

func whoisLookup(c *gin.Context) {
	domain := c.Query("domain")
	if domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain parameter is required"})
		return
	}

	cmd := exec.Command("sh", "-c", "whois "+domain)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	lines := strings.Split(string(out), "\n")
	summary := make(map[string]string)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Domain Name:") ||
			strings.HasPrefix(line, "Registrar:") ||
			strings.HasPrefix(line, "Creation Date:") ||
			strings.HasPrefix(line, "Registry Expiry Date:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				summary[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"domain": domain, "whois": summary})
}

func main() {
	r := gin.Default()

	r.GET("/api/ping", pingHost)
	r.GET("/api/dns/lookup", dnsLookup)
	r.GET("/api/logs/search", searchLogs)
	r.GET("/api/files/list", listFiles)
	r.POST("/api/files/archive", archiveFiles)
	r.POST("/api/network/check", checkPort)
	r.GET("/api/system/info", systemInfo)
	r.GET("/api/whois", whoisLookup)

	_ = strconv.Itoa(0)
	r.Run(":8082")
}
