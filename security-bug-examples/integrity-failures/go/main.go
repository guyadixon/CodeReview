package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"plugin"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"-"`
	Role     string `json:"role"`
	Active   bool   `json:"active"`
}

type Session struct {
	UserID  int   `json:"user_id"`
	Created int64 `json:"created"`
}

type Pipeline struct {
	ID      int           `json:"id"`
	Name    string        `json:"name"`
	Stages  []interface{} `json:"stages"`
	OwnerID int           `json:"owner_id"`
	Created int64         `json:"created"`
	Status  string        `json:"status"`
}

type PluginInfo struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	LoadedBy   int    `json:"loaded_by"`
	LoadedAt   int64  `json:"loaded_at"`
}

var (
	users      = make(map[int]*User)
	sessions   = make(map[string]*Session)
	pipelines  = make(map[int]*Pipeline)
	plugins    = make(map[string]*PluginInfo)
	gobStore   = make(map[string][]byte)
	mu         sync.RWMutex
	userSeq    int64 = 4
	pipeSeq    int64 = 0
)

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:])
}

func init() {
	users[1] = &User{1, "admin", "admin@flowctl.io", sha256Hash("admin2024!"), "admin", true}
	users[2] = &User{2, "mwilson", "mwilson@flowctl.io", sha256Hash("mark_w99"), "engineer", true}
	users[3] = &User{3, "jnguyen", "jnguyen@flowctl.io", sha256Hash("jenny_n!"), "analyst", true}
	users[4] = &User{4, "bsmith", "bsmith@flowctl.io", sha256Hash("bob_s22"), "viewer", false}
}

func generateToken(userID int) string {
	raw := fmt.Sprintf("%d-%d-flowctl", userID, time.Now().UnixMilli())
	h := sha256.Sum256([]byte(raw))
	token := fmt.Sprintf("%x", h[:])[:48]
	mu.Lock()
	sessions[token] = &Session{UserID: userID, Created: time.Now().UnixMilli()}
	mu.Unlock()
	return token
}

func getSession(c *gin.Context) *Session {
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		mu.RLock()
		s := sessions[auth[7:]]
		mu.RUnlock()
		return s
	}
	return nil
}

func main() {
	gob.Register(map[string]interface{}{})
	gob.Register([]interface{}{})

	r := gin.Default()

	r.POST("/api/login", handleLogin)
	r.POST("/api/pipelines", handleCreatePipeline)
	r.GET("/api/pipelines/:id", handleGetPipeline)
	r.POST("/api/pipelines/import", handleImportPipeline)
	r.POST("/api/pipelines/export", handleExportPipeline)
	r.POST("/api/objects/store", handleStoreObject)
	r.GET("/api/objects/:key", handleGetObject)
	r.POST("/api/plugins/load", handleLoadPlugin)
	r.GET("/api/plugins", handleListPlugins)
	r.POST("/api/scripts/run", handleRunScript)
	r.GET("/api/users", handleListUsers)
	r.POST("/api/users", handleCreateUser)

	r.Run(":8008")
}

func handleLogin(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	hash := sha256Hash(body.Password)
	mu.RLock()
	for id, u := range users {
		if u.Username == body.Username && u.Password == hash {
			mu.RUnlock()
			if !u.Active {
				c.JSON(403, gin.H{"error": "Account disabled"})
				return
			}
			token := generateToken(id)
			c.JSON(200, gin.H{"token": token, "user_id": id, "role": u.Role})
			return
		}
	}
	mu.RUnlock()
	c.JSON(401, gin.H{"error": "Invalid credentials"})
}

func handleCreatePipeline(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	var body struct {
		Name   string        `json:"name"`
		Stages []interface{} `json:"stages"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Name == "" {
		c.JSON(400, gin.H{"error": "Pipeline name required"})
		return
	}

	id := int(atomic.AddInt64(&pipeSeq, 1))
	p := &Pipeline{
		ID:      id,
		Name:    body.Name,
		Stages:  body.Stages,
		OwnerID: session.UserID,
		Created: time.Now().UnixMilli(),
		Status:  "draft",
	}

	mu.Lock()
	pipelines[id] = p
	mu.Unlock()

	c.JSON(200, gin.H{"id": id, "name": body.Name, "message": "Pipeline created"})
}

func handleGetPipeline(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid pipeline ID"})
		return
	}

	mu.RLock()
	p := pipelines[id]
	mu.RUnlock()

	if p == nil {
		c.JSON(404, gin.H{"error": "Pipeline not found"})
		return
	}
	c.JSON(200, p)
}

func handleImportPipeline(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	var body struct {
		Payload string `json:"payload"`
		Format  string `json:"format"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Payload == "" {
		c.JSON(400, gin.H{"error": "Payload required"})
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(body.Payload)
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid base64 payload"})
		return
	}

	var pipelineData map[string]interface{}

	switch body.Format {
	case "gob":
		dec := gob.NewDecoder(bytes.NewReader(decoded))
		if err := dec.Decode(&pipelineData); err != nil {
			c.JSON(400, gin.H{"error": "Gob decode failed: " + err.Error()})
			return
		}
	default:
		if err := json.Unmarshal(decoded, &pipelineData); err != nil {
			c.JSON(400, gin.H{"error": "JSON decode failed: " + err.Error()})
			return
		}
	}

	id := int(atomic.AddInt64(&pipeSeq, 1))
	name, _ := pipelineData["name"].(string)
	if name == "" {
		name = "Imported Pipeline"
	}
	stages, _ := pipelineData["stages"].([]interface{})

	p := &Pipeline{
		ID:      id,
		Name:    name,
		Stages:  stages,
		OwnerID: session.UserID,
		Created: time.Now().UnixMilli(),
		Status:  "imported",
	}

	mu.Lock()
	pipelines[id] = p
	mu.Unlock()

	c.JSON(200, gin.H{"id": id, "name": name, "message": "Pipeline imported"})
}

func handleExportPipeline(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	var body struct {
		PipelineID int    `json:"pipeline_id"`
		Format     string `json:"format"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "Pipeline ID required"})
		return
	}

	mu.RLock()
	p := pipelines[body.PipelineID]
	mu.RUnlock()

	if p == nil {
		c.JSON(404, gin.H{"error": "Pipeline not found"})
		return
	}

	exportData := map[string]interface{}{
		"name":   p.Name,
		"stages": p.Stages,
	}

	var buf bytes.Buffer
	format := body.Format
	if format == "" {
		format = "json"
	}

	switch format {
	case "gob":
		enc := gob.NewEncoder(&buf)
		if err := enc.Encode(exportData); err != nil {
			c.JSON(500, gin.H{"error": "Gob encode failed: " + err.Error()})
			return
		}
	default:
		raw, err := json.Marshal(exportData)
		if err != nil {
			c.JSON(500, gin.H{"error": "JSON encode failed: " + err.Error()})
			return
		}
		buf.Write(raw)
	}

	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	c.JSON(200, gin.H{"payload": encoded, "format": format})
}

func handleStoreObject(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	var body struct {
		Key  string      `json:"key"`
		Data interface{} `json:"data"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Key == "" {
		c.JSON(400, gin.H{"error": "Key and data required"})
		return
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(&body.Data); err != nil {
		c.JSON(400, gin.H{"error": "Encoding failed: " + err.Error()})
		return
	}

	mu.Lock()
	gobStore[body.Key] = buf.Bytes()
	mu.Unlock()

	c.JSON(200, gin.H{"key": body.Key, "message": "Object stored"})
}

func handleGetObject(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	key := c.Param("key")
	mu.RLock()
	data, ok := gobStore[key]
	mu.RUnlock()

	if !ok {
		c.JSON(404, gin.H{"error": "Object not found"})
		return
	}

	var value interface{}
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&value); err != nil {
		c.JSON(400, gin.H{"error": "Decode failed: " + err.Error()})
		return
	}

	c.JSON(200, gin.H{"key": key, "value": value})
}

func handleLoadPlugin(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	mu.RLock()
	user := users[session.UserID]
	mu.RUnlock()

	if user.Role != "admin" && user.Role != "engineer" {
		c.JSON(403, gin.H{"error": "Insufficient permissions"})
		return
	}

	var body struct {
		URL  string `json:"url"`
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.URL == "" {
		c.JSON(400, gin.H{"error": "Plugin URL required"})
		return
	}

	pluginName := body.Name
	if pluginName == "" {
		pluginName = "custom-plugin"
	}

	resp, err := http.Get(body.URL)
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to download plugin: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	pluginPath := fmt.Sprintf("/tmp/plugins/%s.so", pluginName)
	pluginBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to read plugin: " + err.Error()})
		return
	}

	if err := writeFile(pluginPath, pluginBytes); err != nil {
		c.JSON(500, gin.H{"error": "Failed to save plugin: " + err.Error()})
		return
	}

	p, err := plugin.Open(pluginPath)
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to load plugin: " + err.Error()})
		return
	}

	initSym, err := p.Lookup("Init")
	if err == nil {
		if initFn, ok := initSym.(func()); ok {
			initFn()
		}
	}

	info := &PluginInfo{
		Name:     pluginName,
		Path:     pluginPath,
		LoadedBy: session.UserID,
		LoadedAt: time.Now().UnixMilli(),
	}

	mu.Lock()
	plugins[pluginName] = info
	mu.Unlock()

	c.JSON(200, gin.H{"message": "Plugin loaded", "plugin": info})
}

func writeFile(path string, data []byte) error {
	dirCmd := exec.Command("mkdir", "-p", fmt.Sprintf("/tmp/plugins"))
	if err := dirCmd.Run(); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func handleRunScript(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	mu.RLock()
	user := users[session.UserID]
	mu.RUnlock()

	if user.Role != "admin" && user.Role != "engineer" {
		c.JSON(403, gin.H{"error": "Insufficient permissions"})
		return
	}

	var body struct {
		Script string `json:"script"`
		Args   string `json:"args"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Script == "" {
		c.JSON(400, gin.H{"error": "Script required"})
		return
	}

	cmd := exec.Command("sh", "-c", body.Script+" "+body.Args)
	output, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(400, gin.H{"error": "Script execution failed", "output": string(output)})
		return
	}

	c.JSON(200, gin.H{"output": string(output)})
}

func handleListPlugins(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	mu.RLock()
	list := make([]*PluginInfo, 0, len(plugins))
	for _, p := range plugins {
		list = append(list, p)
	}
	mu.RUnlock()

	c.JSON(200, gin.H{"plugins": list})
}

func handleListUsers(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	mu.RLock()
	userList := make([]gin.H, 0, len(users))
	for _, u := range users {
		userList = append(userList, gin.H{
			"id":       u.ID,
			"username": u.Username,
			"email":    u.Email,
			"role":     u.Role,
			"active":   u.Active,
		})
	}
	mu.RUnlock()

	c.JSON(200, gin.H{"users": userList})
}

func handleCreateUser(c *gin.Context) {
	session := getSession(c)
	if session == nil {
		c.JSON(401, gin.H{"error": "Authentication required"})
		return
	}

	mu.RLock()
	currentUser := users[session.UserID]
	mu.RUnlock()

	if currentUser.Role != "admin" {
		c.JSON(403, gin.H{"error": "Admin access required"})
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Username == "" || body.Password == "" {
		c.JSON(400, gin.H{"error": "Username and password required"})
		return
	}

	id := int(atomic.AddInt64(&userSeq, 1))
	role := body.Role
	if role == "" {
		role = "viewer"
	}

	u := &User{
		ID:       id,
		Username: body.Username,
		Email:    body.Email,
		Password: sha256Hash(body.Password),
		Role:     role,
		Active:   true,
	}

	mu.Lock()
	users[id] = u
	mu.Unlock()

	c.JSON(200, gin.H{"id": id, "username": body.Username, "message": "User created"})
}
