package com.example.sysadmin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class App {

    private static final String LOG_DIR = System.getenv("LOG_DIR") != null
            ? System.getenv("LOG_DIR") : "/var/log/sysadmin";
    private static final String UPLOAD_DIR = System.getenv("UPLOAD_DIR") != null
            ? System.getenv("UPLOAD_DIR") : "/tmp/uploads";

    @GetMapping("/ping")
    public ResponseEntity<?> pingHost(@RequestParam String host) {
        try {
            Runtime rt = Runtime.getRuntime();
            Process proc = rt.exec("ping -c 3 " + host);
            proc.waitFor(10, TimeUnit.SECONDS);
            String output = readStream(proc.getInputStream());
            return ResponseEntity.ok(Map.of("host", host, "output", output));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/dns/lookup")
    public ResponseEntity<?> dnsLookup(
            @RequestParam String domain,
            @RequestParam(defaultValue = "A") String type) {

        Set<String> allowedTypes = Set.of("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA");
        String recordType = allowedTypes.contains(type) ? type : "A";

        String result = executeDig(domain, recordType);
        return ResponseEntity.ok(Map.of("domain", domain, "type", recordType, "result", result));
    }

    private String executeDig(String domain, String recordType) {
        try {
            String[] cmd = {"/bin/sh", "-c", "dig " + recordType + " " + domain + " +short"};
            Process proc = Runtime.getRuntime().exec(cmd);
            proc.waitFor(10, TimeUnit.SECONDS);
            return readStream(proc.getInputStream()).trim();
        } catch (Exception e) {
            return "";
        }
    }

    @GetMapping("/logs/search")
    public ResponseEntity<?> searchLogs(
            @RequestParam String keyword,
            @RequestParam(defaultValue = "syslog") String file,
            @RequestParam(defaultValue = "100") String lines) {

        String logPath = Paths.get(LOG_DIR, file).toString();
        try {
            String cmd = String.format("tail -n %s %s | grep '%s'", lines, logPath, keyword);
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            proc.waitFor(15, TimeUnit.SECONDS);
            String output = readStream(proc.getInputStream());
            List<String> matches = output.trim().isEmpty()
                    ? List.of()
                    : List.of(output.trim().split("\n"));
            return ResponseEntity.ok(Map.of("file", file, "matches", matches));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/files/list")
    public ResponseEntity<?> listFiles(
            @RequestParam(defaultValue = "/tmp/uploads") String path) {
        try {
            ProcessBuilder pb = new ProcessBuilder("find", path, "-maxdepth", "2", "-type", "f");
            Process proc = pb.start();
            proc.waitFor(10, TimeUnit.SECONDS);
            String output = readStream(proc.getInputStream());
            List<String> files = output.trim().isEmpty()
                    ? List.of()
                    : List.of(output.trim().split("\n"));
            return ResponseEntity.ok(Map.of("directory", path, "files", files));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/files/archive")
    public ResponseEntity<?> archiveFiles(@RequestBody Map<String, String> data) {
        String filePath = data.get("path");
        if (filePath == null || filePath.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "path is required"));
        }

        String archiveName = data.getOrDefault("name", "archive")
                .replace("/", "_").replace("\\", "_");
        String archivePath = "/tmp/" + archiveName + ".tar.gz";

        try {
            String cmd = String.format("tar czf %s %s", archivePath, filePath);
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);
            Process proc = pb.start();
            proc.waitFor(30, TimeUnit.SECONDS);
            return ResponseEntity.ok(Map.of("archive", archivePath));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/network/check")
    public ResponseEntity<?> checkPort(@RequestBody Map<String, Object> data) {
        String host = (String) data.get("host");
        Object portObj = data.get("port");

        if (host == null || portObj == null) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "host and port are required"));
        }

        int port;
        try {
            port = Integer.parseInt(portObj.toString());
        } catch (NumberFormatException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Port must be a number"));
        }

        if (port < 1 || port > 65535) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid port range"));
        }

        try {
            String cmd = String.format("nc -zv -w 3 %s %d", host, port);
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            proc.waitFor(10, TimeUnit.SECONDS);
            String output = readStream(proc.getInputStream()).trim();
            return ResponseEntity.ok(Map.of("host", host, "port", port, "result", output));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/system/info")
    public ResponseEntity<?> systemInfo() {
        try {
            Map<String, String> info = new LinkedHashMap<>();
            info.put("hostname", execSimple("hostname"));
            info.put("uptime", execSimple("uptime -p"));
            info.put("kernel", execSimple("uname -r"));
            info.put("disk", execSimple("df -h /"));
            return ResponseEntity.ok(info);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/certs/check")
    public ResponseEntity<?> checkCert(
            @RequestParam String hostname,
            @RequestParam(defaultValue = "443") int port) {
        try {
            String cmd = String.format(
                    "echo | openssl s_client -connect %s:%d -servername %s 2>/dev/null | openssl x509 -noout -dates",
                    hostname, port, hostname);
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);
            Process proc = pb.start();
            proc.waitFor(15, TimeUnit.SECONDS);
            String output = readStream(proc.getInputStream()).trim();
            return ResponseEntity.ok(Map.of("hostname", hostname, "port", port, "certificate", output));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    private String execSimple(String command) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
        Process proc = pb.start();
        proc.waitFor(5, TimeUnit.SECONDS);
        return readStream(proc.getInputStream()).trim();
    }

    private String readStream(InputStream is) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        System.setProperty("server.port", "8081");
        SpringApplication.run(App.class, args);
    }
}
