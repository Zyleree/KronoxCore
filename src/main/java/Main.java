import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.*;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.TimeUnit;

public class Main {
    private static final Logger LOGGER = Logger.getLogger(Main.class.getName());
    public static final String CONFIG_DIR = "config"; 
    public static final String LOGS_DIR = "logs";  

    public static void main(String[] args) {
        setupDirectories(); 
        setupLogger(); 
        LOGGER.info("Starting the KronoxCore v1");

        ConfigManager configManager = new ConfigManager();
        LinkManager linkManager = new LinkManager(configManager);
        CommandHandler commandHandler = new CommandHandler(linkManager);

        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.print("Enter a command: ");
            String input = scanner.nextLine();

            if (input.equalsIgnoreCase("exit")) {
                LOGGER.info("Exiting the application...");
                break; 
            }

            String result = commandHandler.handleCommand(input);
            System.out.println(result);
        }
        scanner.close();
    }

    private static void setupDirectories() {
      File configDir = new File(CONFIG_DIR);
      if (!configDir.exists()) {
          if (configDir.mkdirs()) {
              LOGGER.info("Config directory created successfully.");
          } else {
              LOGGER.severe("Failed to create config directory.");
          }
      }

      File logsDir = new File(LOGS_DIR);
      if (!logsDir.exists()) {
          if (logsDir.mkdirs()) {
              LOGGER.info("Logs directory created successfully.");
          } else {
              LOGGER.severe("Failed to create logs directory.");
          }
      }
  }

    private static void setupLogger() {
        LogManager.getLogManager().reset();
        LOGGER.setLevel(Level.ALL);

        ConsoleHandler ch = new ConsoleHandler();
        ch.setLevel(Level.ALL);
        LOGGER.addHandler(ch);

        try {
            FileHandler fh = new FileHandler(LOGS_DIR + "/application.log", true);
            fh.setLevel(Level.ALL);
            fh.setFormatter(new SimpleFormatter());
            LOGGER.addHandler(fh);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to create log file", e);
        }
    }
}

class ConfigManager {
    private static final Logger LOGGER = Logger.getLogger(ConfigManager.class.getName());
    private static final String CONFIG_FILE = "config/config.json";
    private static final String BANNED_IPS_FILE = "config/bannedip.json";
    private Config config;
    private Set<String> bannedIPs;
    private Map<String, Long> banExpiry = new HashMap<>(); 

    public ConfigManager() {
        loadConfig();
        loadBannedIPs();
    }

    private void loadConfig() {
        File configFile = new File(CONFIG_FILE);
        if (!configFile.exists()) {
            LOGGER.info("Config file does not exist. Creating default configuration.");
            createDefaultConfig();
        } else {
            try {
                String content = new String(Files.readAllBytes(Paths.get(CONFIG_FILE)));
                config = Config.fromJson(content);
                LOGGER.info("Configuration loaded successfully.");
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Failed to load configuration", e);
            }
        }
    }

    private void loadBannedIPs() {
        File bannedIPsFile = new File(BANNED_IPS_FILE);
        bannedIPs = new HashSet<>();
        if (bannedIPsFile.exists()) {
            try {
                String content = new String(Files.readAllBytes(Paths.get(BANNED_IPS_FILE)));
                String[] ipArray = content.substring(1, content.length() - 1).split(", "); 
                for (String ip : ipArray) {
                    bannedIPs.add(ip.trim());
                }
                LOGGER.info("Banned IPs loaded successfully. Total banned IPs: " + bannedIPs.size());
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Failed to load banned IPs", e);
            }
        }
    }

    public void saveBannedIPs() {
        try {
            Path bannedIPsPath = Paths.get(BANNED_IPS_FILE);
            Files.createDirectories(bannedIPsPath.getParent());
            Files.write(bannedIPsPath, bannedIPs.toString().getBytes());
            LOGGER.info("Banned IPs saved successfully.");
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to save banned IPs", e);
        }
    }

    private void createDefaultConfig() {
        config = new Config();
        config.setAvailablePorts(new ArrayList<>(Arrays.asList(8000, 8001, 8002, 8003, 8004)));
        config.setDdosProtectionEnabled(false);
        config.setDdosTimeoutMinutes(30);
        config.setCorsAllowedOrigins(new ArrayList<>(Arrays.asList("%"))); 
        saveConfig();
    }

    private void saveConfig() {
        try {
            Path configPath = Paths.get(CONFIG_FILE);
            Files.createDirectories(configPath.getParent());
            String json = config.toJson();
            Files.write(configPath, json.getBytes());
            LOGGER.info("Configuration saved successfully.");
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to save configuration", e);
        }
    }

    public List<Integer> getAvailablePorts() {
        return config.getAvailablePorts();
    }

    public void removeAvailablePort(int port) {
        config.getAvailablePorts().remove(Integer.valueOf(port));
        saveConfig();
        LOGGER.info("Port " + port + " removed from available ports.");
    }

    public void addAvailablePort(int port) {
        config.getAvailablePorts().add(port);
        saveConfig();
        LOGGER.info("Port " + port + " added to available ports.");
    }

    public boolean isDdosProtectionEnabled() {
        return config.isDdosProtectionEnabled();
    }

    public void setDdosProtectionEnabled(boolean enabled) {
        config.setDdosProtectionEnabled(enabled);
        saveConfig();
        LOGGER.info("DDoS protection " + (enabled ? "enabled" : "disabled"));
    }

    public int getDdosTimeoutMinutes() {
        return config.getDdosTimeoutMinutes();
    }

    public void setDdosTimeoutMinutes(int minutes) {
        config.setDdosTimeoutMinutes(minutes);
        saveConfig();
        LOGGER.info("DDoS timeout set to " + minutes + " minutes");
    }

    public boolean isIPBanned(String ip) {
        if (bannedIPs.contains(ip)) {
            return true;
        }
        if (banExpiry.containsKey(ip)) {
            if (banExpiry.get(ip) > System.currentTimeMillis()) {
                return true;
            } else {
                banExpiry.remove(ip); 
                return false;
            }
        }
        return false;
    }
    

    public void banIP(String ip) {
        bannedIPs.add(ip);
        saveBannedIPs();
        LOGGER.info("IP " + ip + " banned permanently");
    }
    public void banIP(String ip, long duration, TimeUnit unit) {
        long expiryTime = System.currentTimeMillis() + unit.toMillis(duration);
        banExpiry.put(ip, expiryTime);
        LOGGER.info("IP " + ip + " banned temporarily for " + duration + " " + unit.toString().toLowerCase());
    }
  public List<String> getCorsAllowedOrigins() {
    return config.getCorsAllowedOrigins();
  }
}

class Config {
    private List<Integer> availablePorts;
    private boolean ddosProtectionEnabled;
    private int ddosTimeoutMinutes;
    private List<String> corsAllowedOrigins;

    public List<String> getCorsAllowedOrigins() {
        return corsAllowedOrigins;
    }

    public void setCorsAllowedOrigins(List<String> corsAllowedOrigins) {
        this.corsAllowedOrigins = corsAllowedOrigins;
    }

    public List<Integer> getAvailablePorts() {
        return availablePorts;
    }

    public void setAvailablePorts(List<Integer> availablePorts) {
        this.availablePorts = availablePorts;
    }

    public boolean isDdosProtectionEnabled() {
        return ddosProtectionEnabled;
    }

    public void setDdosProtectionEnabled(boolean ddosProtectionEnabled) {
        this.ddosProtectionEnabled = ddosProtectionEnabled;
    }

    public int getDdosTimeoutMinutes() {
        return ddosTimeoutMinutes;
    }

    public void setDdosTimeoutMinutes(int ddosTimeoutMinutes) {
        this.ddosTimeoutMinutes = ddosTimeoutMinutes;
    }

    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"availablePorts\":[");
        for (int i = 0; i < availablePorts.size(); i++) {
            sb.append(availablePorts.get(i));
            if (i < availablePorts.size() - 1) {
                sb.append(",");
            }
        }
        sb.append("],\"ddosProtectionEnabled\":")
                .append(ddosProtectionEnabled)
                .append(",\"ddosTimeoutMinutes\":")
                .append(ddosTimeoutMinutes)
                .append(",\"corsAllowedOrigins\":[");
        for (int i = 0; i < corsAllowedOrigins.size(); i++) {
            sb.append("\"").append(corsAllowedOrigins.get(i)).append("\"");
            if (i < corsAllowedOrigins.size() - 1) {
                sb.append(",");
            }
        }
        sb.append("]}");
        return sb.toString();
    }

    public static Config fromJson(String json) {
        Config config = new Config();
        String[] parts = json.split("\\[|\\]");
        if (parts.length > 1) {
            String[] portStrings = parts[1].split(",");
            List<Integer> ports = new ArrayList<>();
            for (String portString : portStrings) {
                ports.add(Integer.parseInt(portString.trim()));
            }
            config.setAvailablePorts(ports);
        }

        Pattern corsPattern = Pattern.compile("\"corsAllowedOrigins\":\\[(.*?)\\]");
        Matcher corsMatcher = corsPattern.matcher(json);
        if (corsMatcher.find()) {
            String[] originStrings = corsMatcher.group(1).split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
            List<String> origins = new ArrayList<>();
            for (String originString : originStrings) {
                origins.add(originString.trim().replaceAll("[\"]+", ""));
            }
            config.setCorsAllowedOrigins(origins);
        }

        String[] settings = json.split(",");
        for (String setting : settings) {
            if (setting.contains("ddosProtectionEnabled")) {
                config.setDdosProtectionEnabled(Boolean.parseBoolean(setting.split(":")[1].trim()));
            } else if (setting.contains("ddosTimeoutMinutes")) {
                config.setDdosTimeoutMinutes(Integer.parseInt(setting.split(":")[1].trim().replace("}", "")));
            }
        }
        return config;
    }
}

class LinkManager {
    private static final Logger LOGGER = Logger.getLogger(LinkManager.class.getName());
    private static final String LINKS_FILE = "config/links.json";
    private Map<String, Link> links;
    private ConfigManager configManager;
    private Map<String, IpReputation> ipReputations = new ConcurrentHashMap<>();
    private static final int MAX_REQUESTS_PER_SECOND = 5; 
    private static final long TEMP_BAN_DURATION_MINUTES = 2; 
    private static final String ENCRYPTION_KEY = generateRandomKey(256); 

    private Map<String, Deque<Long>> recentRequests = new ConcurrentHashMap<>(); 

    public LinkManager(ConfigManager configManager) {
        this.configManager = configManager;
        loadLinks();
    }

    private void loadLinks() {
        File linksFile = new File(LINKS_FILE);
        if (!linksFile.exists() || linksFile.length() == 0) {
            links = new HashMap<>();
            LOGGER.info("Links file does not exist or is empty. Starting with no links.");
        } else {
            try {
                String content = new String(Files.readAllBytes(Paths.get(LINKS_FILE)));
                links = Link.fromJsonMap(content);
                LOGGER.info("Links loaded successfully. Total links: " + links.size());
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Failed to load links", e);
                links = new HashMap<>();
            }
        }
    }

    private void saveLinks() {
        try {
            Path linksPath = Paths.get(LINKS_FILE);
            Files.createDirectories(linksPath.getParent());
            String json = Link.toJsonMap(links);
            Files.write(linksPath, json.getBytes());
            LOGGER.info("Links saved successfully.");
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to save links", e);
        }
    }

    private static String generateRandomKey(int keySize) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(keySize); 
            SecretKey key = keyGen.generateKey();
            return Base64.getEncoder().encodeToString(key.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            LOGGER.severe("Error generating encryption key: " + e.getMessage());
            return null;
        }
    }

    public String addLink(String name, String targetAddress, String mode) {
        if (links.containsKey(name)) {
            LOGGER.warning("Attempt to add duplicate link: " + name);
            return "Link with this name already exists.";
        }

        String[] addressParts = targetAddress.split(":");
        if (addressParts.length != 2) {
            LOGGER.warning("Invalid target address format: " + targetAddress);
            return "Invalid target address format. Use IP:PORT.";
        }

        List<Integer> availablePorts = configManager.getAvailablePorts();
        if (availablePorts.isEmpty()) {
            LOGGER.warning("No available ports for new link: " + name);
            return "No available ports.";
        }

        int assignedPort = availablePorts.get(0);
        configManager.removeAvailablePort(assignedPort);

        Link link = new Link(targetAddress, assignedPort, mode);
        links.put(name, link);
        saveLinks();

        LOGGER.info("Link added: " + name + ", Target: " + targetAddress +
                ", Assigned Port: " + assignedPort + ", Mode: " + mode);
        return "Link added successfully. Name: " + name + ", Target: " + targetAddress +
                ", Assigned Port: " + assignedPort + ", Mode: " + mode;
    }

    public String removeLink(String name) {
        Link link = links.remove(name);
        if (link == null) {
            LOGGER.warning("Attempt to remove non-existent link: " + name);
            return "Link not found.";
        }

        configManager.addAvailablePort(link.getAssignedPort());
        saveLinks();
        stopProxyServer(link); 
        LOGGER.info("Link removed: " + name + ", Assigned Port " + link.getAssignedPort()
                + " returned to available ports.");
        return "Link removed successfully. Name: " + name + ", Assigned Port " + link.getAssignedPort()
                + " is now available.";
    }

    public String startLink(String name) {
        Link link = links.get(name);
        if (link == null) {
            LOGGER.warning("Attempt to start non-existent link: " + name);
            return "Link not found.";
        }

        link.setActive(true);
        saveLinks();

        startProxyServer(link);

        LOGGER.info("Link started: " + name + ", Target: " + link.getTargetAddress() + ", Port: "
                + link.getAssignedPort());
        return "Link started successfully. Name: " + name + ", Target: " + link.getTargetAddress() + ", Port: "
                + link.getAssignedPort();
    }

    public String stopLink(String name) {
        Link link = links.get(name);
        if (link == null) {
            LOGGER.warning("Attempt to stop non-existent link: " + name);
            return "Link not found.";
        }

        link.setActive(false);
        saveLinks();

        stopProxyServer(link); 

        LOGGER.info("Link stopped: " + name + ", Target: " + link.getTargetAddress() + ", Port: "
                + link.getAssignedPort());
        return "Link stopped successfully. Name: " + name + ", Target: " + link.getTargetAddress() + ", Port: "
                + link.getAssignedPort();
    }

    private void startProxyServer(Link link) {
        new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(link.getAssignedPort())) {
                LOGGER.info("Proxy server started on port " + link.getAssignedPort() + " for target "
                        + link.getTargetAddress());
                while (link.isActive()) {
                    Socket clientSocket = serverSocket.accept();
                    handleClient(clientSocket, link);
                }
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Failed to start proxy server on port " + link.getAssignedPort(), e);
            }
        }).start();
    }

    private void stopProxyServer(Link link) {

        LOGGER.info("Proxy server on port " + link.getAssignedPort() + " is being stopped.");
    }

    private void handleClient(Socket clientSocket, Link link) {
        String clientIP = ((InetSocketAddress) clientSocket.getRemoteSocketAddress()).getAddress().getHostAddress();
        LOGGER.info("Client connected: " + clientIP);

        if (configManager.isIPBanned(clientIP)) {
            LOGGER.warning("Banned IP detected: " + clientIP + ". Connection dropped.");
            try {
                clientSocket.close();
                return; 
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Failed to close client socket", e);
            }
        }

        if (configManager.isDdosProtectionEnabled() && isDDoSAttack(clientIP)) {
            LOGGER.warning("DDoS attack detected from " + clientIP + "! Connection temporarily blocked.");
            logDDoSAttempt(clientIP);
            configManager.banIP(clientIP, TEMP_BAN_DURATION_MINUTES, TimeUnit.MINUTES);
            try {
                clientSocket.close();
                return; 
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Failed to close client socket", e);
            }
        }

        try {
            if (!handleCors(clientSocket, link)) {
                return; 
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Error handling CORS: " + e.getMessage());
            return;
        }

        new Thread(() -> {
            String targetAddress = link.getTargetAddress();
            String[] addressParts = targetAddress.split(":");
            String targetHost = addressParts[0];
            int targetPort = Integer.parseInt(addressParts[1]);

            try (Socket targetSocket = new Socket(targetHost, targetPort)) {
                LOGGER.info("Proxying connection from " + clientSocket.getRemoteSocketAddress() + " to " + targetHost + ":"
                        + targetPort);

                InputStream clientInput = clientSocket.getInputStream();
                OutputStream clientOutput = clientSocket.getOutputStream();
                InputStream targetInput = targetSocket.getInputStream();
                OutputStream targetOutput = targetSocket.getOutputStream();

                if (link.getMode().equals("forward")) {
                    new Thread(() -> forwardData(clientInput, targetOutput)).start();
                    forwardData(targetInput, clientOutput);
                } else if (link.getMode().equals("ddosprot")) {
                    handleDDoSProtectedConnection(clientSocket, targetSocket); 
                } else if (link.getMode().equals("filterddosprot")) {
                    handleFilteredDDoSProtectedConnection(clientSocket, targetHost, targetPort, clientIP);
                }
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Error in proxy connection to " + targetAddress + ": " + e.getMessage());
            } finally {
                try {
                    clientSocket.close();
                } catch (IOException e) {
                    LOGGER.log(Level.WARNING, "Failed to close client socket", e);
                }
            }
        }).start();
    }

    private boolean handleCors(Socket clientSocket, Link link) throws IOException {
        InputStream clientInput = clientSocket.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(clientInput));
        OutputStream clientOutput = clientSocket.getOutputStream();

        String origin = null;
        String requestMethod = null;
        String requestHeaders = null;
        String line;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            if (line.startsWith("Origin: ")) {
                origin = line.substring("Origin: ".length());
            } else if (line.startsWith("Access-Control-Request-Method: ")) {
                requestMethod = line.substring("Access-Control-Request-Method: ".length());
            } else if (line.startsWith("Access-Control-Request-Headers: ")) {
                requestHeaders = line.substring("Access-Control-Request-Headers: ".length());
            }

            if (origin != null && (requestMethod != null || !link.getMode().equals("filterddosprot"))) {
                break;
            }
        }

        List<String> allowedOrigins = configManager.getCorsAllowedOrigins();
        boolean allowAllOrigins = allowedOrigins.contains("%");

        if (origin != null && (allowAllOrigins || allowedOrigins.contains(origin))) {
            clientOutput.write("HTTP/1.1 200 OK\r\n".getBytes());
            clientOutput.write(("Access-Control-Allow-Origin: " + origin + "\r\n").getBytes());
            clientOutput.write("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n".getBytes());
            clientOutput.write("Access-Control-Allow-Headers: Content-Type, Authorization\r\n".getBytes());
            clientOutput.write("\r\n".getBytes());
            clientOutput.flush();

            if (requestMethod != null) {
                clientSocket.close();
                return false;
            }
        } else if (origin != null) {
            clientOutput.write("HTTP/1.1 403 Forbidden\r\n".getBytes());
            clientOutput.write("\r\n".getBytes());
            clientOutput.flush();
            clientSocket.close();
            return false;
        }

        return true;
    }

    private void forwardData(InputStream input, OutputStream output) {
        try {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = input.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
                output.flush();
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Data forwarding error: " + e.getMessage());
        }
    }

    private boolean isDDoSAttack(String ip) {
        long currentTime = System.currentTimeMillis();
        int requestWindowSeconds = 1;

        Deque<Long> requestTimes = recentRequests.computeIfAbsent(ip, k -> new LinkedList<>());
        requestTimes.addLast(currentTime);

        while (!requestTimes.isEmpty() && currentTime - requestTimes.getFirst() > requestWindowSeconds * 1000) {
            requestTimes.removeFirst();
        }

        if (requestTimes.size() > MAX_REQUESTS_PER_SECOND) {
            LOGGER.warning("Rate limiting triggered for IP: " + ip + ". Request count: " + requestTimes.size());
            return true;
        }
        return false;
    }

    private void logDDoSAttempt(String ip) {
        try {
            Files.createDirectories(Paths.get(Main.LOGS_DIR)); 
            FileWriter writer = new FileWriter(Main.LOGS_DIR + "/ddoslogs.txt", true);
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
            LocalDateTime now = LocalDateTime.now();
            writer.write("[" + dtf.format(now) + "] Potential DDoS attack detected from: " + ip + "\n");
            writer.close();
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to log DDoS attempt", e);
        }
    }

    private String encryptRequest(String request, String key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(request.getBytes());
        return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encrypted);
    }

    private String decryptResponse(InputStream inputStream, String key) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String encryptedResponse = reader.readLine();
        if (encryptedResponse == null) {
            return "";
        }

        String[] parts = encryptedResponse.split(":");
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] encryptedBytes = Base64.getDecoder().decode(parts[1]);

        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

        byte[] decrypted = cipher.doFinal(encryptedBytes);
        return new String(decrypted);
    }

    private void handleDDoSProtectedConnection(Socket clientSocket, Socket targetSocket) { 
        try {
            InputStream clientInput = clientSocket.getInputStream();
            OutputStream clientOutput = clientSocket.getOutputStream();
            InputStream targetInput = targetSocket.getInputStream();
            OutputStream targetOutput = targetSocket.getOutputStream();

            new Thread(() -> forwardData(clientInput, targetOutput)).start();
            forwardData(targetInput, clientOutput);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error in DDoS protected connection: " + e.getMessage());
        }
    }

    private void handleFilteredDDoSProtectedConnection(Socket clientSocket, String targetHost, int targetPort, String clientIP) {
        try {
            InputStream clientInput = clientSocket.getInputStream();
            String rawRequest = readRequest(clientInput);
            String sanitizedRequest = sanitizeRequest(rawRequest, clientIP);
            if (sanitizedRequest == null) {
                LOGGER.warning("Request sanitization failed. Dropping connection.");
                clientSocket.close();
                return;
            }

            String encryptedRequest = encryptRequest(sanitizedRequest, ENCRYPTION_KEY);

            Socket targetSocket = new Socket(targetHost, targetPort);
            OutputStream targetOutput = targetSocket.getOutputStream();
            PrintWriter targetWriter = new PrintWriter(targetOutput, true);
            targetWriter.print(encryptedRequest);

            InputStream targetInput = targetSocket.getInputStream();
            OutputStream clientOutput = clientSocket.getOutputStream();
            String decryptedResponse = decryptResponse(targetInput, ENCRYPTION_KEY);
            clientOutput.write(decryptedResponse.getBytes());
            clientOutput.flush();

            targetSocket.close();
            clientSocket.close();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in filtered DDoS protected connection", e);
        }
    }


    private String readRequest(InputStream inputStream) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        StringBuilder requestBuilder = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            requestBuilder.append(line).append("\r\n");
        }
        requestBuilder.append("\r\n"); 
        return requestBuilder.toString();
    }

    private String sanitizeRequest(String request, String clientIP) {
        String sanitizedRequest = removeMaliciousHeaders(request);
        sanitizedRequest = sanitizeCookies(sanitizedRequest, clientIP);
        return sanitizedRequest;
    }

    private String removeMaliciousHeaders(String request) {
        List<String> blacklistedHeaders = Arrays.asList("cookie", "referer", "user-agent", 
                "x-forwarded-for", "x-forwarded-host");
        StringBuilder sanitizedRequest = new StringBuilder();
        String[] lines = request.split("\r\n");
        for (String line : lines) {
            if (line.isEmpty()) {
                sanitizedRequest.append(line).append("\r\n");
                continue;
            }
            boolean headerIsBlacklisted = blacklistedHeaders.stream()
                    .anyMatch(blacklistedHeader -> line.toLowerCase().startsWith(blacklistedHeader + ":"));
            if (!headerIsBlacklisted) {
                sanitizedRequest.append(line).append("\r\n");
            } else {
                LOGGER.warning("Removed potentially malicious header: " + line);
            }
        }
        return sanitizedRequest.toString();
    }

    private String sanitizeCookies(String request, String clientIP) {
        List<String> newCookies = new ArrayList<>();
        String[] lines = request.split("\r\n");
        for (String line : lines) {
            if (line.toLowerCase().startsWith("cookie: ")) {
                String[] cookies = line.substring("Cookie: ".length()).split("; ");
                for (String cookie : cookies) {
                    String[] parts = cookie.split("=", 2);
                    if (parts.length == 2) {
                        String name = parts[0].trim();
                        String value = parts[1].trim();

                        if (isValidCookieValue(value)) {
                            newCookies.add(name + "=" + value);
                        } else {
                            LOGGER.warning("Removed potentially malicious cookie from " + clientIP + ": " + cookie); 
                        }
                    }
                }
            }
        }
        if (!newCookies.isEmpty()) {
            String newCookieHeader = "Cookie: " + String.join("; ", newCookies) + "\r\n";
            request = request.replaceAll("(?i)cookie: .*?\r\n", newCookieHeader); 
        }
        return request;
    }

    private boolean isValidCookieValue(String cookieValue) {
        return cookieValue.matches("^[a-zA-Z0-9-_. ]+$"); 
    }
}

class Link {
    private String targetAddress;
    private int assignedPort;
    private boolean active;
    private String mode;

    public Link(String targetAddress, int assignedPort, String mode) {
        this.targetAddress = targetAddress;
        this.assignedPort = assignedPort;
        this.active = false;
        this.mode = mode;
    }

    public String getTargetAddress() {
        return targetAddress;
    }

    public int getAssignedPort() {
        return assignedPort;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public static Map<String, Link> fromJsonMap(String json) {
        Map<String, Link> map = new HashMap<>();
        json = json.replace("{", "").replace("}", "").replace("\"", "");
        String[] entries = json.split(",");
        for (String entry : entries) {
            String[] parts = entry.split(":");
            if (parts.length == 4) { 
                String name = parts[0];
                String targetAddress = parts[1];
                int assignedPort = Integer.parseInt(parts[2]);
                String mode = parts[3];
                map.put(name, new Link(targetAddress, assignedPort, mode));
            }
        }
        return map;
    }

    public static String toJsonMap(Map<String, Link> map) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        int i = 0;
        for (Map.Entry<String, Link> entry : map.entrySet()) {
            sb.append("\"").append(entry.getKey()).append("\":{\"targetAddress\":\"")
                    .append(entry.getValue().getTargetAddress()).append("\",\"assignedPort\":")
                    .append(entry.getValue().getAssignedPort()).append(",\"mode\":\"")
                    .append(entry.getValue().getMode()).append("\"}");
            if (i < map.size() - 1) {
                sb.append(",");
            }
            i++;
        }
        sb.append("}");
        return sb.toString();
    }
}
class IpReputation {
    public Queue<Long> requests = new LinkedList<>();
    public int score = 100; 

    public void updateScore(int points) {
        this.score += points;
        if (this.score < 0) {
            this.score = 0;
        } else if (this.score > 100) {
            this.score = 100;
        }
    }
}

class CommandHandler {
    private static final Logger LOGGER = Logger.getLogger(CommandHandler.class.getName());
    private LinkManager linkManager;

    public CommandHandler(LinkManager linkManager) {
        this.linkManager = linkManager;
    }

    public String handleCommand(String input) {
        String[] parts = input.split(" ");
        String command = parts[0];

        switch (command) {
            case "linkadd":
                if (parts.length == 5
                        && (parts[4].equals("forward") || parts[4].equals("ddosprot") || parts[4].equals("filterddosprot"))) {
                    return linkManager.addLink(parts[1], parts[2], parts[4]);
                } else {
                    return "Usage: linkadd <name> <targetAddress:port> <mode(forward/ddosprot/filterddosprot)>";
                }
            case "linkremove":
                if (parts.length == 2) {
                    return linkManager.removeLink(parts[1]);
                } else {
                    return "Usage: linkremove <name>";
                }
            case "linkstart":
                if (parts.length == 2) {
                    return linkManager.startLink(parts[1]);
                } else {
                    return "Usage: linkstart <name>";
                }
            case "linkstop":
                if (parts.length == 2) {
                    return linkManager.stopLink(parts[1]);
                } else {
                    return "Usage: linkstop <name>";
                }
            default:
                return "Unknown command. Available commands: linkadd, linkremove, linkstart, linkstop";
        }
    }
}