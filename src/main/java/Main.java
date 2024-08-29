import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.logging.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.*;
import javax.crypto.spec.*;

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

        try (Scanner scanner = new Scanner(System.in)) {
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
        }
    }

    private static void setupDirectories() {
        createDirectoryIfNotExist(CONFIG_DIR);
        createDirectoryIfNotExist(LOGS_DIR);
    }

    private static void createDirectoryIfNotExist(String directoryPath) {
        File directory = new File(directoryPath);
        if (!directory.exists()) {
            if (directory.mkdirs()) { 
                LOGGER.info(String.format("%s directory created successfully.", directoryPath));
            } else {
                LOGGER.severe(String.format("Failed to create %s directory.", directoryPath));
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
            LOGGER.log(Level.SEVERE, String.format("Failed to create log file: %s",
                    e.getMessage()), e); 
        }
    }
}

class ConfigManager {
    private static final Logger LOGGER = Logger.getLogger(ConfigManager.class.getName());
    private static final String CONFIG_FILE = "config/config.json";
    private static final String BANNED_IPS_FILE = "config/bannedip.json";
    private Config config;
    private final Set<String> bannedIPs = new HashSet<>();
    private final Map<String, Long> banExpiry = new HashMap<>();
    private final String encryptionKey;

    public ConfigManager() {
        loadConfig(); 
        loadBannedIPs();

        if (config.getEncryptionKey() == null || config.getEncryptionKey().isEmpty()) {
            LOGGER.info("Generating new encryption key...");
            encryptionKey = generateRandomKey(256);
            config.setEncryptionKey(encryptionKey);
            saveConfig(); 
        } else {
            encryptionKey = config.getEncryptionKey(); 
        }
    }

    private void loadConfig() {
        File configFile = new File(CONFIG_FILE); 
        if (!configFile.exists()) {
            LOGGER.info("Config file does not exist. Creating default configuration.");
            createDefaultConfig(); 
        } else {
            try {
                String content = Files.readString(Paths.get(CONFIG_FILE));
                config = Config.fromJson(content);
                LOGGER.info("Configuration loaded successfully.");
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Failed to load configuration: " + 
                            e.getMessage(), e); 
            }
        }
    }

    private void loadBannedIPs() {
        File bannedIPsFile = new File(BANNED_IPS_FILE);
        if (bannedIPsFile.exists()) {
            try {
                String content = Files.readString(Paths.get(BANNED_IPS_FILE)); 
                String[] ipArray = content.substring(1, content.length() - 1).split(", ");
                bannedIPs.addAll(Arrays.asList(ipArray)); 
                LOGGER.info(String.format("Banned IPs loaded successfully. Total banned IPs: %d",
                                           bannedIPs.size())); 
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Failed to load banned IPs: " +
                           e.getMessage(), e); 
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
            LOGGER.log(Level.SEVERE, "Failed to save banned IPs: " +
                       e.getMessage(), e);
        }
    }

    private void createDefaultConfig() {
        config = new Config(); 
        config.setAvailablePorts(new ArrayList<>(Arrays.asList(8000, 8001, 8002, 8003, 8004)));
        config.setDdosProtectionEnabled(false); 
        config.setDdosTimeoutMinutes(30); 
        config.setCorsAllowedOrigins(new ArrayList<>(Arrays.asList("%"))); 
        config.setEncryptionKey("");
        saveConfig(); 
    }

    private void saveConfig() {
        try {
            Path configPath = Paths.get(CONFIG_FILE);
            Files.createDirectories(configPath.getParent()); 
            String json = config.toJson();
            Files.writeString(configPath, json); 
            LOGGER.info("Configuration saved successfully.");
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, String.format("Failed to save configuration: %s",
                                                     e.getMessage()), e);
        }
    }

    public List<Integer> getAvailablePorts() {
        return config.getAvailablePorts(); 
    }

    public void removeAvailablePort(int port) {
        config.getAvailablePorts().remove(Integer.valueOf(port)); 
        saveConfig();
        LOGGER.info(String.format("Port %d removed from available ports.", port));
    }

    public void addAvailablePort(int port) {
        config.getAvailablePorts().add(port);
        saveConfig(); 
        LOGGER.info(String.format("Port %d added to available ports.", port));
    }

    public boolean isDdosProtectionEnabled() {
        return config.isDdosProtectionEnabled(); 
    }

    public void setDdosProtectionEnabled(boolean enabled) {
        config.setDdosProtectionEnabled(enabled);
        saveConfig(); 
        LOGGER.info(String.format("DDoS protection %s", enabled ? "enabled" : "disabled"));
    }

    public int getDdosTimeoutMinutes() {
        return config.getDdosTimeoutMinutes();
    }

    public void setDdosTimeoutMinutes(int minutes) {
        config.setDdosTimeoutMinutes(minutes);
        saveConfig();
        LOGGER.info(String.format("DDoS timeout set to %d minutes", minutes));
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
        LOGGER.info(String.format("IP %s banned permanently", ip));
    }

    public void banIP(String ip, long duration, TimeUnit unit) {
        long expiryTime = System.currentTimeMillis() + unit.toMillis(duration);
        banExpiry.put(ip, expiryTime); 
        LOGGER.info(String.format("IP %s banned temporarily for %d %s",
                                   ip, duration, unit.toString().toLowerCase())); 
    }

    public List<String> getCorsAllowedOrigins() {
        return config.getCorsAllowedOrigins();
    }

    public String getEncryptionKey() {
        return encryptionKey; 
    }

    private String generateRandomKey(int keySize) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(keySize); 
            SecretKey key = keyGen.generateKey();
            return Base64.getEncoder().encodeToString(key.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            LOGGER.log(Level.SEVERE, String.format("Error generating encryption key: %s",
                    e.getMessage()), e);
            return null;
        }
    }
}

class Config {
    private List<Integer> availablePorts;
    private boolean ddosProtectionEnabled; 
    private int ddosTimeoutMinutes;
    private List<String> corsAllowedOrigins;
    private String encryptionKey;

    public Config() {
        this.encryptionKey = ""; 
    }

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

    public String getEncryptionKey() {
        return encryptionKey;
    }

    public void setEncryptionKey(String encryptionKey) {
        this.encryptionKey = encryptionKey;
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
        sb.append(String.format("],\"ddosProtectionEnabled\":%b," +
                                "\"ddosTimeoutMinutes\":%d," +
                                "\"corsAllowedOrigins\":[", 
                                ddosProtectionEnabled, ddosTimeoutMinutes)); 
        
        for (int i = 0; i < corsAllowedOrigins.size(); i++) {
            sb.append(String.format("\"%s\"", corsAllowedOrigins.get(i)));
            if (i < corsAllowedOrigins.size() - 1) {
                sb.append(",");
            }
        }
        sb.append(String.format("],\"encryptionKey\":\"%s\"}", encryptionKey));
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
            String[] originStrings = corsMatcher.group(1)
                                           .split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)"); 
            List<String> origins = new ArrayList<>(); 
            for (String originString : originStrings) {
                origins.add(originString.trim().replaceAll("[\"]+", "")); 
            }
            config.setCorsAllowedOrigins(origins); 
        }

        Pattern encryptionKeyPattern = Pattern.compile("\"encryptionKey\":\"(.*?)\"");
        Matcher encryptionKeyMatcher = encryptionKeyPattern.matcher(json);
        if (encryptionKeyMatcher.find()) {
            config.setEncryptionKey(encryptionKeyMatcher.group(1));
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
    private final ConfigManager configManager;
    private static final int MAX_REQUESTS_PER_SECOND = 5;
    private static final long TEMP_BAN_DURATION_MINUTES = 2; 
    private static final String BLOCKED_CONTENT_FILE = "config/blocked_content.json";
    private final Set<String> blockedContent = new HashSet<>();
    private final Map<String, Deque<Long>> recentRequests = new ConcurrentHashMap<>();

    public LinkManager(ConfigManager configManager) {
        this.configManager = configManager;
        loadLinks(); 
        loadBlockedContent();
    }

    private void loadLinks() {
        File linksFile = new File(LINKS_FILE); 
        if (!linksFile.exists() || linksFile.length() == 0) {
            links = new HashMap<>();
            LOGGER.info("Links file does not exist or is empty. Starting with no links.");
        } else {
            try {
                String content = Files.readString(Paths.get(LINKS_FILE)); 
                links = Link.fromJsonMap(content);
                LOGGER.info(String.format("Links loaded successfully. Total links: %d",
                        links.size())); 
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, String.format("Failed to load links: %s", 
                                                        e.getMessage()), e); 
                links = new HashMap<>();
            }
        }
    }

    private void saveLinks() {
        try {
            Path linksPath = Paths.get(LINKS_FILE);
            Files.createDirectories(linksPath.getParent());
            String json = Link.toJsonMap(links);
            Files.writeString(linksPath, json);
            LOGGER.info("Links saved successfully."); 
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, String.format("Failed to save links: %s",
                    e.getMessage()), e); 
        }
    }

    private void loadBlockedContent() {
        File blockedContentFile = new File(BLOCKED_CONTENT_FILE);
        if (blockedContentFile.exists()) {
            try (FileReader reader = new FileReader(BLOCKED_CONTENT_FILE); 
                BufferedReader bufferedReader = new BufferedReader(reader)) { 
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    line = line.trim(); 
                    if (!line.isEmpty()) {
                        blockedContent.add(line); 
                    }
                }
                LOGGER.info(String.format("Blocked content loaded successfully. Total blocked entries: %d",
                        blockedContent.size()));
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Error loading blocked content: " +
                            e.getMessage(), e);
            }
        } else {
            LOGGER.warning("Blocked content file not found. Creating an empty file.");
            try {
                if (blockedContentFile.createNewFile()) {
                    LOGGER.info("Blocked content file created successfully"); 
                } else {
                    LOGGER.warning("Blocked content file already exists."); 
                }
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, String.format("Error creating blocked content file: %s",
                                                       e.getMessage()), e);
            }
        }
    }

    public void blockContent(String content) {
        if (content == null || content.trim().isEmpty()) { 
            return; 
        }
        blockedContent.add(content.trim());
        saveBlockedContent();
        LOGGER.info(String.format("Content blocked: %s", content)); 
    }

    private void saveBlockedContent() {
        try (FileWriter writer = new FileWriter(BLOCKED_CONTENT_FILE)) { 
            for (String content : blockedContent) { 
                writer.write(content + System.lineSeparator()); 
            }
            LOGGER.info("Blocked content list saved successfully."); 
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, String.format("Error saving blocked content: %s",
                                                     e.getMessage()), e); 
        }
    }


    public String addLink(String name, String targetAddress, String mode) {
        if (!isValidLinkName(name)) {
            return "Invalid link name. Use alphanumeric characters and hyphens only."; 
        }

        if (!isValidTargetAddress(targetAddress)) {
            return "Invalid target address format. Use IP:PORT.";
        }

        if (links.containsKey(name)) {
            LOGGER.warning(String.format("Attempt to add duplicate link: %s", name)); 
            return "Link with this name already exists."; 
        }

        String[] addressParts = targetAddress.split(":");
        if (addressParts.length != 2) {
            LOGGER.warning(String.format("Invalid target address format: %s", targetAddress));
            return "Invalid target address format. Use IP:PORT.";
        }

        List<Integer> availablePorts = configManager.getAvailablePorts(); 
        if (availablePorts.isEmpty()) { 
            LOGGER.warning(String.format("No available ports for new link: %s", name)); 
            return "No available ports.";
        }

        int assignedPort = availablePorts.get(0);
        configManager.removeAvailablePort(assignedPort);

        Link link = new Link(targetAddress, assignedPort, mode); 
        links.put(name, link);
        saveLinks();

        LOGGER.info(String.format("Link added: %s, Target: %s, Assigned Port: %d, Mode: %s",
                                    name, targetAddress, assignedPort, mode));
        return String.format("Link added successfully. " + 
                               "Name: %s, Target: %s, Assigned Port: %d, Mode: %s", 
                               name, targetAddress, assignedPort, mode); 
    }

    public String removeLink(String name) {
        Link link = links.remove(name); 
        if (link == null) {
            LOGGER.warning(String.format("Attempt to remove non-existent link: %s", name)); 
            return "Link not found.";
        }

        configManager.addAvailablePort(link.getAssignedPort());
        saveLinks();
        stopProxyServer(link); 
        LOGGER.info(String.format("Link removed: %s, Assigned Port %d returned to available ports.",
                                  name, link.getAssignedPort())); 
        return String.format("Link removed successfully. Name: %s, Assigned Port %d is now available.", 
                             name, link.getAssignedPort()); 
    }

    public String startLink(String name) {
        Link link = links.get(name);
        if (link == null) {
            LOGGER.warning(String.format("Attempt to start non-existent link: %s", name)); 
            return "Link not found."; 
        }

        link.setActive(true); 
        saveLinks(); 

        startProxyServer(link); 

        LOGGER.info(String.format("Link started: %s, Target: %s, Port: %d", 
                                   name, link.getTargetAddress(), link.getAssignedPort())); 
        return String.format("Link started successfully. Name: %s, Target: %s, Port: %d", 
                               name, link.getTargetAddress(), link.getAssignedPort());
    }

    public String stopLink(String name) {
        Link link = links.get(name);
        if (link == null) {
            LOGGER.warning(String.format("Attempt to stop non-existent link: %s", name)); 
            return "Link not found.";
        }

        link.setActive(false); 
        saveLinks(); 

        stopProxyServer(link); 

        LOGGER.info(String.format("Link stopped: %s, Target: %s, Port: %d",
                name, link.getTargetAddress(), link.getAssignedPort()));
        return String.format("Link stopped successfully. " +
                             "Name: %s, Target: %s, Port: %d", 
                             name, link.getTargetAddress(), link.getAssignedPort()); 
    }

    private void startProxyServer(Link link) {
        new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(link.getAssignedPort())) {
                LOGGER.info(String.format("Proxy server started on port %d for target %s", 
                                         link.getAssignedPort(), link.getTargetAddress())); 
                while (link.isActive()) {
                    try (Socket clientSocket = serverSocket.accept()) {
                        handleClient(clientSocket, link); 
                    } catch (IOException e) {
                        LOGGER.log(Level.WARNING, String.format("Error accepting client connection: %s",
                                                                e.getMessage()), e); 
                    }
                }
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, String.format("Failed to start proxy server on port %d: %s",
                        link.getAssignedPort(), e.getMessage()), e);
            }
        }).start();
    }

    private void stopProxyServer(Link link) {
        LOGGER.info(String.format("Proxy server on port %d is being stopped.",
                                   link.getAssignedPort())); 
    }

    private void handleClient(Socket clientSocket, Link link) {
        String clientIP = ((InetSocketAddress) clientSocket.getRemoteSocketAddress())
                .getAddress().getHostAddress(); 
        LOGGER.info(String.format("Client connected: %s", clientIP)); 

        if (configManager.isIPBanned(clientIP)) {
            LOGGER.warning(String.format("Banned IP detected: %s. Connection dropped.", clientIP));
            try {
                clientSocket.close(); 
                return; 
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, String.format("Failed to close client socket: %s", 
                        e.getMessage()), e); 
            }
        }


        try {
            if (!handleCors(clientSocket, link)) {
                return; 
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, String.format("Error handling CORS: %s",
                    e.getMessage()), e);
            return; 
        }

        new Thread(() -> {
            String targetAddress = link.getTargetAddress(); 
            String[] addressParts = targetAddress.split(":");
            String targetHost = addressParts[0]; 
            int targetPort = Integer.parseInt(addressParts[1]); 

            try (Socket targetSocket = new Socket(targetHost, targetPort); 
                 InputStream clientInput = clientSocket.getInputStream(); 
                 OutputStream clientOutput = clientSocket.getOutputStream(); 
                 InputStream targetInput = targetSocket.getInputStream(); 
                 OutputStream targetOutput = targetSocket.getOutputStream()) { 
                
                LOGGER.info(String.format("Proxying connection from %s to %s:%d", 
                                        clientSocket.getRemoteSocketAddress(), targetHost, targetPort)); 

                switch (link.getMode()) {
                    case "forward" -> { 
                        new Thread(() -> forwardData(clientInput, targetOutput)).start();
                        forwardData(targetInput, clientOutput); 
                    }
                    case "ddosprot" -> handleDDoSProtectedConnection(clientSocket, targetSocket, clientIP);
                    case "filterddosprot" -> handleFilteredDDoSProtectedConnection(clientSocket, targetHost, targetPort, clientIP);
                    default -> LOGGER.severe(String.format("Unknown link mode: %s", link.getMode()));
                } 
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, String.format("Error in proxy connection to %s, Error: %s", 
                        targetAddress, e.getMessage()), e);
            }
        }).start();
    }

    private boolean handleCors(Socket clientSocket, Link link) throws IOException {
        try (InputStream clientInput = clientSocket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(clientInput)); 
            OutputStream clientOutput = clientSocket.getOutputStream()) {

            String origin = null; 
            String requestMethod = null;
            String line; 
            while ((line = reader.readLine()) != null && !line.isEmpty()) { 
                if (line.startsWith("Origin: ")) {
                    origin = line.substring("Origin: ".length());
                } else if (line.startsWith("Access-Control-Request-Method: ")) {
                    requestMethod = line.substring("Access-Control-Request-Method: ".length()); 
                }

                if (origin != null && (requestMethod != null || !link.getMode().equals("filterddosprot"))) { 
                    break; 
                }
            }

            List<String> allowedOrigins = configManager.getCorsAllowedOrigins();
            boolean allowAllOrigins = allowedOrigins.contains("%"); 

            if (origin != null && (allowAllOrigins || allowedOrigins.contains(origin))) { 
                clientOutput.write("HTTP/1.1 200 OK\r\n".getBytes()); 
                clientOutput.write(String.format("Access-Control-Allow-Origin: %s\r\n", origin) 
                                     .getBytes()); 
                clientOutput.write("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n" 
                                     .getBytes()); 
                clientOutput.write("Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                                    .getBytes()); 
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
            LOGGER.log(Level.WARNING, String.format("Data forwarding error: %s", 
                                                   e.getMessage()), e);
        }
    }

    private boolean isDDoSAttack(String ip, String path) {
        long currentTime = System.currentTimeMillis();
        int requestWindowSeconds = 1; 

        String key = ip + "-" + path;
        Deque<Long> requestTimes = recentRequests.computeIfAbsent(key, k -> new LinkedList<>());
        requestTimes.addLast(currentTime);

        while (!requestTimes.isEmpty() &&
               currentTime - requestTimes.getFirst() > requestWindowSeconds * 1000) { 
            requestTimes.removeFirst();
        }

        if (requestTimes.size() > MAX_REQUESTS_PER_SECOND) { 
            LOGGER.warning(String.format("Rate limiting triggered for IP: %s on path: %s. Request count: %d",
                                           ip, path, requestTimes.size())); 
            return true; 
        }
        return false;
    }

    private void logDDoSAttempt(String ip) {
        try (FileWriter writer = new FileWriter(Main.LOGS_DIR + "/ddoslogs.txt", true)) { 
            Files.createDirectories(Paths.get(Main.LOGS_DIR)); 
            DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
            LocalDateTime now = LocalDateTime.now(); 
            writer.write(String.format("[%s] Potential DDoS attack detected from: %s%n", 
                                       dtf.format(now), ip));
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, String.format("Failed to log DDoS attempt: %s", 
                                                     e.getMessage()), e);
        }
    }

    private String encryptRequest(String request, String key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES"); 
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); 
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        byte[] iv = cipher.getIV();
        byte[] encrypted = cipher.doFinal(request.getBytes());
        return Base64.getEncoder().encodeToString(iv) + ":" +
               Base64.getEncoder().encodeToString(encrypted); 
    }

    private String decryptResponse(InputStream inputStream, String key) throws Exception {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) { 
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
    }

    private void handleDDoSProtectedConnection(Socket clientSocket, Socket targetSocket, 
                                            String clientIP) { 
        try (InputStream clientInput = clientSocket.getInputStream();
             OutputStream clientOutput = clientSocket.getOutputStream(); 
             InputStream targetInput = targetSocket.getInputStream(); 
             OutputStream targetOutput = targetSocket.getOutputStream(); 
             BufferedReader reader = new BufferedReader(new InputStreamReader(clientInput))) { 

            String requestLine = reader.readLine(); 

            if (requestLine != null) {
                String[] requestParts = requestLine.split(" ");
                if (requestParts.length > 1) { 
                    String path = requestParts[1];
                    if (isDDoSAttack(clientIP, path)) { 
                        configManager.banIP(clientIP, TEMP_BAN_DURATION_MINUTES, TimeUnit.MINUTES);
                        clientSocket.close(); 
                        LOGGER.warning(String.format("DDoS attack detected from %s on path %s! " + 
                                                      "Connection temporarily blocked.", 
                                                     clientIP, path)); 
                        logDDoSAttempt(clientIP); 
                        return; 
                    }
                }
            }

            new Thread(() -> forwardData(clientInput, targetOutput)).start();
            forwardData(targetInput, clientOutput); 
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, String.format("Error in DDoS protected connection: %s", 
                                                   e.getMessage()), e); 
        } 
    }

    private void handleFilteredDDoSProtectedConnection(Socket clientSocket, String targetHost,
                                                       int targetPort, String clientIP) { 
        try (Socket targetSocket = new Socket(targetHost, targetPort);
             InputStream clientInput = clientSocket.getInputStream();
             OutputStream clientOutput = clientSocket.getOutputStream();
             OutputStream targetOutput = targetSocket.getOutputStream(); 
             PrintWriter targetWriter = new PrintWriter(targetOutput, true); 
             InputStream targetInput = targetSocket.getInputStream()) {

            String rawRequest = readRequest(clientInput); 
            String sanitizedRequest = sanitizeRequest(rawRequest, clientIP); 
            if (sanitizedRequest == null) { 
                LOGGER.warning("Request sanitization failed. Dropping connection.");
                clientSocket.close();
                return;
            }

            String encryptedRequest = encryptRequest(sanitizedRequest, configManager.getEncryptionKey()); 
            targetWriter.print(encryptedRequest);
            targetWriter.flush();

            String decryptedResponse = decryptResponse(targetInput, configManager.getEncryptionKey()); 
            clientOutput.write(decryptedResponse.getBytes()); 
            clientOutput.flush(); 

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, String.format("Error in filtered DDoS protected connection: %s",
                                                    e.getMessage()), e);
        }
    }

    private String readRequest(InputStream inputStream) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            StringBuilder requestBuilder = new StringBuilder();
            String line           ;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                requestBuilder.append(line).append("\r\n");
            }
            requestBuilder.append("\r\n");
            return requestBuilder.toString();
        }
    }

    private String sanitizeRequest(String request, String clientIP) {
        String sanitizedRequest = removeMaliciousHeaders(request);
        sanitizedRequest = sanitizeCookies(sanitizedRequest, clientIP);
        sanitizedRequest = filterBlockedContent(sanitizedRequest);
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
                LOGGER.warning(String.format("Removed potentially malicious header: %s", line));
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
                            LOGGER.warning(String.format("Removed potentially malicious cookie from %s: %s",
                                    clientIP, cookie));
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
        // Basic validation - you might need more specific rules 
        return cookieValue.matches("^[a-zA-Z0-9-_=%.; ]+$");
    }

    private String filterBlockedContent(String request) {
        for (String blocked : blockedContent) {
            if (request.contains(blocked)) {
                LOGGER.warning(String.format("Blocked content detected: %s", blocked));
                return "Request Blocked"; 
            }
        }
        return request;
    }

    private boolean isValidLinkName(String name) {
        return name.matches("^[a-zA-Z0-9-]+$"); 
    }

    private boolean isValidTargetAddress(String address) {
        // Validate IP:PORT format
        return address.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d+$");
    }
}

class Link {
    private final String targetAddress; 
    private final int assignedPort;
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
                String name = parts[0].trim();
                String targetAddress = parts[1].trim(); 
                int assignedPort = Integer.parseInt(parts[2].trim());
                String mode = parts[3].trim(); 
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
            sb.append(String.format("\"%s\":{\"targetAddress\":\"%s\"," + 
                            "\"assignedPort\":%d,\"mode\":\"%s\"}",
                    entry.getKey(), entry.getValue().getTargetAddress(), 
                    entry.getValue().getAssignedPort(), entry.getValue().getMode()));
            if (i < map.size() - 1) { 
                sb.append(",");
            }
            i++; 
        }
        sb.append("}"); 
        return sb.toString();
    }
}

class CommandHandler {
    private final LinkManager linkManager;

    public CommandHandler(LinkManager linkManager) {
        this.linkManager = linkManager;
    }

    public String handleCommand(String input) {
        String[] parts = input.split(" "); 
        if (parts.length == 0) {
            return "Invalid command.";
        }
        String command = parts[0].toLowerCase();

        return switch (command) { 
            case "linkadd" -> {
                if (parts.length == 5 && 
                    (parts[4].equals("forward") || 
                     parts[4].equals("ddosprot") || 
                     parts[4].equals("filterddosprot"))) {
                    yield linkManager.addLink(parts[1], parts[2], parts[4]); 
                } else {
                    yield "Usage: linkadd <name> <targetAddress:port> <mode(forward/ddosprot/filterddosprot)>"; 
                }
            }
            case "linkremove" -> {
                if (parts.length == 2) {
                    yield linkManager.removeLink(parts[1]); 
                } else {
                    yield "Usage: linkremove <name>";
                }
            }
            case "linkstart" -> {
                if (parts.length == 2) { 
                    yield linkManager.startLink(parts[1]); 
                } else {
                    yield "Usage: linkstart <name>"; 
                }
            }
            case "linkstop" -> {
                if (parts.length == 2) { 
                    yield linkManager.stopLink(parts[1]);
                } else {
                    yield "Usage: linkstop <name>";
                }
            }
            case "blockcontent" -> {
                if (parts.length > 1) {
                    String contentToBlock = String.join(" ", Arrays.copyOfRange(parts, 1, parts.length));
                    linkManager.blockContent(contentToBlock);
                    yield String.format("Content blocked: %s", contentToBlock);
                } else {
                    yield "Usage: blockcontent <content_to_block>"; 
                }
            }
            default -> """
                       Unknown command. Available commands:
                       - linkadd, linkremove, linkstart, linkstop
                       - blockcontent"""; 
        }; 
    }
}