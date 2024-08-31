package com.zyleree.kronoxcore; 

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import org.bson.Document;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;
import java.util.stream.Collectors;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Main {
    private static final Logger LOGGER = Logger.getLogger(Main.class.getName()); 
    public static final String CONFIG_DIR = "config";
    public static final String LOGS_DIR = "logs"; 

    public static void main(String[] args) { 
        setupDirectories();
        setupLogger(); 
        LOGGER.info("Starting KronoxCore v1");

        ConfigManager configManager = new ConfigManager();
        NetworkManager networkManager = new NetworkManager(configManager);
        networkManager.setupNetwork();

        LinkManager linkManager = new LinkManager(configManager);
        CommandHandler commandHandler = new CommandHandler(linkManager, configManager, networkManager); 

        try (Scanner scanner = new Scanner(System.in)) { 
            while (true) { 
                System.out.print("Enter a command: ");
                String input = scanner.nextLine();

                if (input.equalsIgnoreCase("exit")) { 
                    LOGGER.info("Exiting the application...");
                    linkManager.shutdown();
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
    private static final String CONFIG_FILE = "config/config.properties"; 
    private static final String BANNED_IPS_FILE = "config/bannedip.json";
    private Properties properties = new Properties(); 
    private final Set<String> bannedIPs = new HashSet<>(); 
    private final Map<String, Long> banExpiry = new HashMap<>();
    private String encryptionKey; 

    public ConfigManager() { 
        loadConfig();
        loadBannedIPs(); 

        encryptionKey = getEncryptionKey();

        if (encryptionKey == null || encryptionKey.isEmpty()) {
            LOGGER.info("Generating new encryption key...");
            encryptionKey = generateRandomKey(256); 
            setEncryptionKey(encryptionKey);
            saveConfig();
        }
    } 

    private void loadConfig() { 
        File configFile = new File(CONFIG_FILE);
        if (!configFile.exists()) { 
            LOGGER.info("Config file does not exist. Creating default configuration.");
            createDefaultConfig(); 
        } else {
            try (InputStream inputStream = new FileInputStream(configFile)) { 
                properties.load(inputStream);
                LOGGER.info("Configuration loaded successfully.");
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, String.format("Failed to load configuration: %s", 
                                                     e.getMessage()), e);
            }
        }
    }

    public List<Integer> parsePorts(String portsString) {
        List<Integer> ports = new ArrayList<>();
        if (portsString != null) { 
            String[] portParts = portsString.split(","); 
            for (String portPart : portParts) {
                try { 
                    ports.add(Integer.parseInt(portPart.trim()));
                } catch (NumberFormatException e) { 
                    LOGGER.warning(String.format("Invalid port number: %s. Skipping.", portPart));
                }
            }
        } 
        return ports; 
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
                LOGGER.log(Level.SEVERE, String.format("Failed to load banned IPs: %s",
                                                      e.getMessage()), e); 
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
            LOGGER.log(Level.SEVERE, "Failed to save banned IPs: " + e.getMessage(), e);
        } 
    }

    private void createDefaultConfig() {
        properties.setProperty("availablePorts", "8000,8001,8002,8003,8004");
        properties.setProperty("ddosProtectionEnabled", "false");
        properties.setProperty("ddosTimeoutMinutes", "30"); 
        properties.setProperty("corsAllowedOrigins", "%"); 
        properties.setProperty("encryptionKey", ""); 
        properties.setProperty("httpOnly", "false"); 
        properties.setProperty("secureCookie", "false"); 
        properties.setProperty("defaultCsrfProtection", "false");
        properties.setProperty("kronoxPort", "9999");
        properties.setProperty("mongoDbUrl", "mongodb://localhost:27017"); 
        properties.setProperty("instanceName", ""); 
        properties.setProperty("instanceId", "");
        properties.setProperty("apiKey", "");
        properties.setProperty("fleetMode", "false"); 
        saveConfig();
    }

    private void saveConfig() { 
        File configFile = new File(CONFIG_FILE);
        try (OutputStream outputStream = new FileOutputStream(configFile)) { 
            properties.store(outputStream, null);
            LOGGER.info("Configuration saved successfully.");
        } catch (IOException e) { 
            LOGGER.log(Level.SEVERE, String.format("Failed to save configuration: %s",
                                                   e.getMessage()), e);
        }
    } 

    public void reloadConfig() {
        loadConfig(); 
        LOGGER.info("Configuration reloaded successfully.");
    }

    public List<Integer> getAvailablePorts() {
        return parsePorts(properties.getProperty("availablePorts")); 
    } 

    public void removeAvailablePort(int port) {
        List<Integer> ports = getAvailablePorts(); 
        ports.remove((Integer) port); 
        properties.setProperty("availablePorts", ports.stream()
                .map(String::valueOf)
                .collect(Collectors.joining(",")));
        saveConfig();
        LOGGER.info(String.format("Port %d removed from available ports.", port)); 
    }

    public void addAvailablePort(int port) {
        List<Integer> ports = getAvailablePorts(); 
        ports.add(port);
        properties.setProperty("availablePorts", ports.stream() 
                .map(String::valueOf)
                .collect(Collectors.joining(",")));
        saveConfig();
        LOGGER.info(String.format("Port %d added to available ports.", port)); 
    }

    public boolean isDdosProtectionEnabled() {
        return Boolean.parseBoolean(properties.getProperty("ddosProtectionEnabled"));
    }

    public void setDdosProtectionEnabled(boolean enabled) { 
        properties.setProperty("ddosProtectionEnabled", String.valueOf(enabled));
        saveConfig(); 
        LOGGER.info(String.format("DDoS protection %s", enabled ? "enabled" : "disabled"));
    }

    public int getDdosTimeoutMinutes() { 
        return Integer.parseInt(properties.getProperty("ddosTimeoutMinutes")); 
    } 

    public void setDdosTimeoutMinutes(int minutes) {
        properties.setProperty("ddosTimeoutMinutes", String.valueOf(minutes)); 
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
        return Arrays.asList(properties.getProperty("corsAllowedOrigins").split(","));
    } 

    public String getEncryptionKey() { 
        return properties.getProperty("encryptionKey");
    }

    public void setEncryptionKey(String encryptionKey) { 
        properties.setProperty("encryptionKey", encryptionKey); 
        saveConfig(); 
    }

    public boolean isHttpOnly() {
        return Boolean.parseBoolean(properties.getProperty("httpOnly")); 
    } 

    public void setHttpOnly(boolean httpOnly) { 
        properties.setProperty("httpOnly", String.valueOf(httpOnly)); 
        saveConfig(); 
    }

    public boolean isSecureCookie() { 
        return Boolean.parseBoolean(properties.getProperty("secureCookie"));
    } 

    public void setSecureCookie(boolean secureCookie) {
        properties.setProperty("secureCookie", String.valueOf(secureCookie)); 
        saveConfig();
    }

    public boolean isDefaultCsrfProtection() { 
        return Boolean.parseBoolean(properties.getProperty("defaultCsrfProtection")); 
    }

    public void setDefaultCsrfProtection(boolean defaultCsrfProtection) { 
        properties.setProperty("defaultCsrfProtection", String.valueOf(defaultCsrfProtection));
        saveConfig(); 
    }

    public int getKronoxPort() { 
        return Integer.parseInt(properties.getProperty("kronoxPort"));
    } 

    public void setKronoxPort(int kronoxPort) {
        properties.setProperty("kronoxPort", String.valueOf(kronoxPort)); 
        saveConfig();
    } 

    public String getInstanceName() { 
        return properties.getProperty("instanceName");
    } 

    public void setInstanceName(String instanceName) {
        properties.setProperty("instanceName", instanceName);
        saveConfig();
    }

    public String getInstanceId() {
        return properties.getProperty("instanceId");
    }

    public void setInstanceId(String instanceId) {
        properties.setProperty("instanceId", instanceId);
        saveConfig(); 
    }

    public String getApiKey() {
        return properties.getProperty("apiKey");
    }

    public void setApiKey(String apiKey) {
        properties.setProperty("apiKey", apiKey);
        saveConfig(); 
    } 

    public String getMongoDbUrl() {
        return properties.getProperty("mongoDbUrl"); 
    }

    public void setMongoDbUrl(String mongoDbUrl) {
        properties.setProperty("mongoDbUrl", mongoDbUrl);
        saveConfig();
    } 

    public boolean isFleetModeEnabled() { 
        return Boolean.parseBoolean(properties.getProperty("fleetMode"));
    } 

    public void setFleetMode(boolean enabled) { 
        properties.setProperty("fleetMode", String.valueOf(enabled));
        saveConfig(); 
    }

    private String generateRandomKey(int keySize) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(keySize); 
            SecretKey key = keyGen.generateKey();
            return Base64.getEncoder().encodeToString(key.getEncoded()); 
        } catch (NoSuchAlgorithmException e) {
            LOGGER.log(Level.SEVERE, "Error generating encryption key: " +
                       e.getMessage(), e); 
            return null; 
        } 
    } 
} 

class NetworkManager { 
    private static final Logger LOGGER = Logger.getLogger(NetworkManager.class.getName());
    private final ConfigManager configManager; 
    private MongoClient mongoClient; 
    private MongoDatabase database;
    private MongoCollection<Document> networkCollection; 

    public NetworkManager(ConfigManager configManager) {
        this.configManager = configManager; 
    } 

    public void setupNetwork() { 
        try (Scanner scanner = new Scanner(System.in)) {
            if (isFirstRun()) { 
                System.out.print("Enter a name for this KronoxCore instance: ");
                String instanceName = scanner.nextLine();
                configManager.setInstanceName(instanceName); 
                System.out.print("Enable Fleet Mode? (yes/no): "); 
                String enableFleetMode = scanner.nextLine().toLowerCase(); 

                if (enableFleetMode.equals("yes")) {
                    promptForMongoDbUrl(scanner);

                    connectToMongoDB(); 
                    registerInstance(); 
                    configManager.setFleetMode(true); 
                } else {
                    LOGGER.info("Fleet Mode disabled."); 
                    configManager.setFleetMode(false); 
                } 
            } else if (configManager.isFleetModeEnabled() && 
                       (configManager.getMongoDbUrl().isEmpty() || !testMongoDBConnection())) {
                LOGGER.warning("Fleet Mode is enabled, but the MongoDB connection URL is missing or invalid.");
                promptForMongoDbUrl(scanner); 
                connectToMongoDB(); 
                registerInstance();
            }
            if (configManager.isFleetModeEnabled()) {
                pingNetworkInstances(); 
            }
        }
    } 

    private void promptForMongoDbUrl(Scanner scanner) { 
        String mongoDbUrl = configManager.getMongoDbUrl(); 
        while (mongoDbUrl.isEmpty() || !testMongoDBConnection()) {
            System.out.print("Enter the MongoDB connection URL: "); 
            mongoDbUrl = scanner.nextLine();
            configManager.setMongoDbUrl(mongoDbUrl);

            if (!testMongoDBConnection()) {
                LOGGER.severe("Invalid MongoDB URL. Please try again.");
            }
        } 
    }

    public boolean isFirstRun() { 
        return configManager.getInstanceName().isEmpty(); 
    } 

    public void connectToMongoDB() { 
        String mongoDbUrl = configManager.getMongoDbUrl();
        ConnectionString connectionString = new ConnectionString(mongoDbUrl); 
        MongoClientSettings settings = MongoClientSettings.builder()
                .applyConnectionString(connectionString) 
                .build();
        mongoClient = MongoClients.create(settings);
        database = mongoClient.getDatabase("KronoxCore");
        networkCollection = database.getCollection("network");

        LOGGER.info("Connected to MongoDB successfully.");
    }

    private boolean testMongoDBConnection() { 
        String mongoDbUrl = configManager.getMongoDbUrl();
        if (mongoDbUrl.isEmpty()) {
            return false;
        } 
        try (MongoClient mongoClient = MongoClients.create(mongoDbUrl)) {
            mongoClient.listDatabaseNames().first();
            return true; 
        } catch (Exception e) {
            return false; 
        } 
    }

    public void registerInstance() { 
        String instanceId = configManager.getInstanceId(); 
        String apiKey = configManager.getApiKey(); 

        if (instanceId.isEmpty() || apiKey.isEmpty()) { 
            instanceId = generateInstanceId(); 
            apiKey = generateApiKey(); 
        } 

        String publicIp = getPublicIP(); 
        int kronoxPort = configManager.getKronoxPort(); 
        String instanceAddress = publicIp + ":" + kronoxPort; 

        Document existingInstance = networkCollection.find(Filters.eq("name",
                configManager.getInstanceName())).first();

        if (existingInstance != null) { 
            LOGGER.info("Instance name already exists. Updating details.");
            networkCollection.updateOne(Filters.eq("_id", existingInstance.get("_id")),
                    new Document("$set", new Document("id", instanceId) 
                            .append("apiKey", apiKey)
                            .append("ip", instanceAddress))); 
        } else { 
            Document instanceData = new Document("name", configManager.getInstanceName())
                    .append("id", instanceId)
                    .append("apiKey", apiKey) 
                    .append("ip", instanceAddress);

            networkCollection.insertOne(instanceData);
            LOGGER.info(String.format("KronoxCore instance registered successfully with ID: %s and address: %s",
                    instanceId, instanceAddress));
        } 

        configManager.setInstanceId(instanceId); 
        configManager.setApiKey(apiKey);
    } 

    public List<Document> getNetworkInstances() { 
        return networkCollection.find().into(new ArrayList<>()); 
    } 

    public void pingNetworkInstances() {
        List<Document> instances = getNetworkInstances(); 
        List<String> reachableInstances = new ArrayList<>(); 
        for (Document instance : instances) { 
            if (!instance.getString("name").equals(configManager.getInstanceName())) { 
                String instanceName = instance.getString("name"); 
                String instanceAddress = instance.getString("ip");

                if (pingServer(instanceAddress)) {
                    reachableInstances.add(instanceName + " (" + instanceAddress + ")"); 
                }
            } 
        }

        if (!reachableInstances.isEmpty()) {
            LOGGER.info("The following KronoxCore instances are reachable and ready to accept traffic:"); 
            LOGGER.info(String.join(", ", reachableInstances)); 
        } else { 
            LOGGER.info("No other reachable KronoxCore instances found."); 
        } 
    }

    private boolean pingServer(String serverAddress) { 
        try {
            String[] parts = serverAddress.split(":"); 
            String host = parts[0];
            int port = Integer.parseInt(parts[1]);
            Socket socket = new Socket(host, port); 
            socket.close();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private String generateInstanceId() {
        return UUID.randomUUID().toString().replace("-", ""); 
    }

    private String generateApiKey() {
        byte[] randomBytes = new byte[28]; 
        new Random().nextBytes(randomBytes);
        return bytesToHex(randomBytes);
    }

    private String bytesToHex(byte[] bytes) { 
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) { 
            sb.append(String.format("%02x", b)); 
        } 
        return sb.toString();
    } 

    private String getPublicIP() {
        try (Socket socket = new Socket("google.com", 80)) {
            return ((InetSocketAddress) socket.getLocalSocketAddress()).getAddress().getHostAddress();
        } catch (IOException e) { 
            LOGGER.log(Level.SEVERE, "Failed to get public IP: " + e.getMessage(), e); 
            return "Unknown IP";
        }
    }
} 
class LinkManager { 
    private static final Logger LOGGER = Logger.getLogger(LinkManager.class.getName()); 
    private static final String LINKS_FILE = "config/links.properties"; 
    private static final int MAX_REQUESTS_PER_SECOND = 5; 
    private static final long TEMP_BAN_DURATION_MINUTES = 2;
    private static final String BLOCKED_CONTENT_FILE = "config/blocked_content.json";
    private final Set<String> blockedContent = new HashSet<>();
    private final Map<String, Deque<Long>> recentRequests = new ConcurrentHashMap<>();
    private final Map<String, Link> links = new ConcurrentHashMap<>();
    private final ConfigManager configManager;
    private final ExecutorService threadPool = Executors.newFixedThreadPool(10);
    private Selector selector;

    public LinkManager(ConfigManager configManager) { 
        this.configManager = configManager;
        loadLinks(); 
        loadBlockedContent();
        try { 
            selector = Selector.open(); 
            LOGGER.info("Selector opened successfully."); 
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error opening selector: " + e.getMessage(), e);
        }
    } 

    public void shutdown() {
        threadPool.shutdown(); 
        try {
            if (!threadPool.awaitTermination(5, TimeUnit.SECONDS)) { 
                threadPool.shutdownNow();
            }
        } catch (InterruptedException e) {
            LOGGER.log(Level.SEVERE, "Error during thread pool shutdown: " + e.getMessage(), e); 
            threadPool.shutdownNow(); 
        } 

        try { 
            if (selector != null) { 
                selector.close(); 
            } 
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error closing selector: " + e.getMessage(), e); 
        }
    }

    private void loadLinks() { 
        File linksFile = new File(LINKS_FILE);
        if (!linksFile.exists() || linksFile.length() == 0) {
            LOGGER.info("Links file does not exist or is empty. Starting with no links.");
        } else {
            try (InputStream inputStream = new FileInputStream(linksFile)) {
                Properties properties = new Properties();
                properties.load(inputStream); 

                for (String key : properties.stringPropertyNames()) {
                    if (key.startsWith("link.")) {
                        String linkName = key.substring("link.".length());
                        String[] linkParts = properties.getProperty(key).split(","); 

                        if (linkParts.length >= 6) { 
                            String targetAddress = linkParts[0].trim(); 
                            int assignedPort = Integer.parseInt(linkParts[1].trim());
                            String mode = linkParts[2].trim(); 
                            boolean active = Boolean.parseBoolean(linkParts[3].trim()); 
                            boolean csrfProtection = Boolean.parseBoolean(linkParts[4].trim());
                            String csrfToken = linkParts[5].trim(); 

                            Link link = new Link(targetAddress, assignedPort, mode, active,
                                                csrfProtection, csrfToken); 
                            links.put(linkName, link); 

                            if (active) {
                                startProxyServer(link);
                            }
                        } else { 
                            LOGGER.warning(String.format("Invalid link definition in config file: %s", key));
                        }
                    } 
                }

                LOGGER.info(String.format("Links loaded successfully. Total links: %d", 
                                          links.size()));
            } catch (IOException e) { 
                LOGGER.log(Level.SEVERE, String.format("Failed to load links: %s", 
                                                       e.getMessage()), e); 
            } catch (NumberFormatException e) {
                LOGGER.log(Level.SEVERE, "Invalid port number in links file: " +
                           e.getMessage(), e); 
            }
        } 
    }

    private void saveLinks() { 
        File linksFile = new File(LINKS_FILE);
        try (OutputStream outputStream = new FileOutputStream(linksFile)) { 
            Properties properties = new Properties(); 

            for (Map.Entry<String, Link> entry : links.entrySet()) {
                String linkName = entry.getKey(); 
                Link link = entry.getValue();

                String linkData = String.format("%s,%d,%s,%b,%b,%s",
                        link.getTargetAddress(), link.getAssignedPort(), link.getMode(),
                        link.isActive(), link.isCsrfProtection(), link.getCsrfToken()); 

                properties.setProperty("link." + linkName, linkData);
            }

            properties.store(outputStream, null);
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
                LOGGER.info(String.format("Blocked content loaded successfully. " + 
                                          "Total blocked entries: %d", blockedContent.size())); 
            } catch (IOException e) { 
                LOGGER.log(Level.SEVERE, "Error loading blocked content: " +
                                                         e.getMessage(), e); 
            } 
        } else {
            LOGGER.warning("Blocked content file not found. Creating an empty file.");
            try {
                if (blockedContentFile.createNewFile()) {
                    LOGGER.info("Blocked content file created successfully."); 
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
            LOGGER.log(Level.SEVERE, "Error saving blocked content: " + 
                       e.getMessage(), e); 
        } 
    }


    public String addLink(String name, String targetAddress, String mode) { 
        if (!isValidLinkName(name)) { 
            return "Invalid link name. Use alphanumeric characters, hyphens, and underscores only."; 
        } 

        if (!isValidTargetAddress(targetAddress)) { 
            return "Invalid target address format. Use IP:PORT (e.g., 192.168.1.10:8080).";
        }

        if (links.containsKey(name)) {
            return "Link with this name already exists."; 
        }

        String[] addressParts = targetAddress.split(":"); 
        if (addressParts.length != 2) { 
            return "Invalid target address format. Use IP:PORT (e.g., 192.168.1.10:8080).";
        }

        List<Integer> availablePorts = configManager.getAvailablePorts();
        if (availablePorts.isEmpty()) {
            LOGGER.warning("No available ports.");
            return "No available ports."; 
        }

        int assignedPort = availablePorts.get(0);
        configManager.removeAvailablePort(assignedPort); 

        Link link = new Link(targetAddress, assignedPort, mode);
        links.put(name, link); 
        saveLinks(); 
        LOGGER.info(String.format("Link added: %s, Target: %s, Assigned Port: %d, Mode: %s",
                name, targetAddress, assignedPort, mode));
        return String.format("Link added successfully. Name: %s, Target: %s, Assigned Port: %d, Mode: %s",
                name, targetAddress, assignedPort, mode); 
    }

    public String removeLink(String name) {
        Link link = links.remove(name);
        if (link == null) { 
            LOGGER.warning(String.format("Link not found: %s", name)); 
            return "Link not found."; 
        } 

        configManager.addAvailablePort(link.getAssignedPort());
        saveLinks(); 

        if (link.isActive()) {
            stopProxyServer(link);
        }

        LOGGER.info(String.format("Link removed: %s", name));
        return "Link removed successfully.";
    } 

    public String startLink(String name) { 
        Link link = links.get(name); 
        if (link == null) { 
            LOGGER.warning(String.format("Link not found: %s", name)); 
            return "Link not found.";
        }

        if (link.isActive()) { 
            return "Link is already running."; 
        }

        link.setActive(true); 
        saveLinks();

        startProxyServer(link);

        LOGGER.info(String.format("Link started: %s", name)); 
        return "Link started successfully.";
    }

    public String stopLink(String name) { 
        Link link = links.get(name);
        if (link == null) { 
            LOGGER.warning(String.format("Link not found: %s", name));
            return "Link not found."; 
        } 

        if (!link.isActive()) {
            return "Link is not running.";
        }

        link.setActive(false);
        saveLinks();

        stopProxyServer(link);

        LOGGER.info(String.format("Link stopped: %s", name)); 
        return "Link stopped successfully."; 
    } 

    private void startProxyServer(Link link) { 
        threadPool.execute(() -> { 
            try (ServerSocketChannel serverSocketChannel = ServerSocketChannel.open()) { 
                serverSocketChannel.configureBlocking(false); 
                serverSocketChannel.bind(new InetSocketAddress(link.getAssignedPort())); 

                serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);

                LOGGER.info(String.format("Proxy server started on port %d for target %s", 
                        link.getAssignedPort(), link.getTargetAddress()));

                while (link.isActive()) {
                    selector.select();
                    Set<SelectionKey> selectedKeys = selector.selectedKeys();
                    Iterator<SelectionKey> keyIterator = selectedKeys.iterator(); 

                    while (keyIterator.hasNext()) { 
                        SelectionKey key = keyIterator.next();
                        keyIterator.remove();

                        if (!key.isValid()) { 
                            continue; 
                        }

                        if (key.isAcceptable()) { 
                            acceptConnection(key, link); 
                        } else if (key.isReadable()) {
                            readFromClient(key, link); 
                        } else if (key.isWritable()) {
                            writeToClient(key); 
                        } 
                    }
                } 

            } catch (IOException e) { 
                LOGGER.log(Level.SEVERE, String.format("Failed to start proxy server on port %d: %s",
                        link.getAssignedPort(), e.getMessage()), e); 
            }
        });
    } 

    private void acceptConnection(SelectionKey key, Link link) throws IOException {
        ServerSocketChannel serverSocketChannel = (ServerSocketChannel) key.channel(); 
        try (SocketChannel clientChannel = serverSocketChannel.accept()) { 
            clientChannel.configureBlocking(false);

            String clientIP = ((InetSocketAddress) clientChannel.getRemoteAddress())
                                               .getAddress().getHostAddress();

            LOGGER.info(String.format("Client connected: %s                                    on port %d", 
                                    clientIP, link.getAssignedPort()));

            clientChannel.register(selector, SelectionKey.OP_READ, new ClientData(link, clientIP)); 
        }
    }

    private void readFromClient(SelectionKey key, Link link) { 
        try (SocketChannel clientChannel = (SocketChannel) key.channel()) { 
            ClientData clientData = (ClientData) key.attachment();
            ByteBuffer buffer = ByteBuffer.allocate(8192);

            int bytesRead = clientChannel.read(buffer); 
            if (bytesRead == -1) { 
                LOGGER.info(String.format("Client disconnected: %s from port %d",
                                             clientData.clientIP, link.getAssignedPort()));
                return; 
            }

            buffer.flip();
            String rawRequest = StandardCharsets.UTF_8.decode(buffer).toString(); 

            logRequest(clientData.clientIP, rawRequest, link);

            if (link.getMode().equals("filterddosprot")) {
                handleFilteredDDoSProtectedConnection(clientChannel, clientData, rawRequest);
            } else {
                handleNonFilteredConnection(clientChannel, clientData, rawRequest, link);
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, String.format("Error reading from client: %s", 
                                                    e.getMessage()), e); 
        }
    } 

    private void writeToClient(SelectionKey key) throws IOException {
        SocketChannel clientChannel = (SocketChannel) key.channel();
        ClientData clientData = (ClientData) key.attachment(); 
        ByteBuffer buffer = clientData.responseQueue.poll();

        if (buffer != null) { 
            clientChannel.write(buffer);
            if (buffer.hasRemaining()) {
                key.interestOps(SelectionKey.OP_WRITE); 
            } else { 
                key.interestOps(SelectionKey.OP_READ); 
            } 
        } 
    }

    private void handleNonFilteredConnection(SocketChannel clientChannel, ClientData clientData, 
                                              String rawRequest, Link link) { 
        String targetAddress = link.getTargetAddress();
        String[] addressParts = targetAddress.split(":"); 
        String targetHost = addressParts[0];
        int targetPort = Integer.parseInt(addressParts[1]); 

        try (Socket targetSocket = new Socket(targetHost, targetPort); 
             InputStream targetInput = targetSocket.getInputStream();
             OutputStream targetOutput = targetSocket.getOutputStream()) {

            if (link.getMode().equals("forward")) {
                threadPool.execute(() -> forwardData(clientChannel, clientData, targetOutput)); 
                forwardData(targetInput, clientChannel, clientData); 
            } else if (link.getMode().equals("ddosprot")) { 
                handleDDoSProtectedConnection(clientChannel, clientData, targetSocket);
            } else {
                LOGGER.severe("Unknown link mode: " + link.getMode()); 
                clientChannel.close(); 
            }
        } catch (IOException e) { 
            LOGGER.log(Level.SEVERE, String.format("Error in proxy connection to %s, Error: %s",
                    targetAddress, e.getMessage()), e);
            try {
                clientChannel.close();
            } catch (IOException ex) { 
                LOGGER.log(Level.SEVERE, String.format("Error closing client channel: %s",
                        ex.getMessage()), ex);
            }
        }
    } 

    private void handleFilteredDDoSProtectedConnection(SocketChannel clientChannel, 
                                                         ClientData clientData, 
                                                         String rawRequest) { 
        String targetAddress = clientData.link.getTargetAddress();
        String[] addressParts = targetAddress.split(":"); 
        String targetHost = addressParts[0];
        int targetPort = Integer.parseInt(addressParts[1]);

        threadPool.execute(() -> {
            try (SocketChannel targetChannel = SocketChannel.open();
                 InputStream targetInput = targetChannel.socket().getInputStream();
                 OutputStream targetOutput = targetChannel.socket().getOutputStream()) { 

                targetChannel.configureBlocking(false); 
                if (targetChannel.connect(new InetSocketAddress(targetHost, targetPort))) {
                    while (!targetChannel.finishConnect()) {
                    } 

                    String sanitizedRequest = sanitizeRequest(rawRequest, clientData.clientIP);
                    if (sanitizedRequest == null) {
                        LOGGER.warning(String.format("Request sanitization failed for %s on port %d. Dropping connection.", 
                                               clientData.clientIP, clientData.link.getAssignedPort())); 
                        clientChannel.close(); 
                        return; 
                    } 

                    String encryptedRequest;
                    try {
                        encryptedRequest = encryptRequest(sanitizedRequest);
                    } catch (Exception e) {
                        LOGGER.log(Level.SEVERE, String.format("Error encrypting request: %s", 
                                e.getMessage()), e);
                        clientChannel.close();
                        return; 
                    } 

                    PrintWriter targetWriter = new PrintWriter(targetOutput, true);
                    targetWriter.print(encryptedRequest); 
                    targetWriter.flush(); 

                    String decryptedResponse; 
                    try { 
                        decryptedResponse = decryptResponse(targetInput); 
                    } catch (Exception e) { 
                        LOGGER.log(Level.SEVERE, "Error decrypting response: " + 
                                e.getMessage(), e); 
                        clientChannel.close();
                        return; 
                    } 

                    sendResponseToClient(clientChannel, clientData, decryptedResponse);

                } else {
                    LOGGER.severe(String.format("Failed to connect to %s:%d for filtered connection.", 
                            targetHost, targetPort));
                    clientChannel.close(); 
                } 
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, String.format("Error in filtered connection to %s: %s",
                                                        targetAddress, e.getMessage()), e);
                try {
                    clientChannel.close();
                } catch (IOException ex) { 
                    LOGGER.log(Level.SEVERE, String.format("Error closing client channel: %s", 
                                                          ex.getMessage()), ex); 
                } 
            }
        }); 
    }

    private void handleDDoSProtectedConnection(SocketChannel clientChannel,
                                                 ClientData clientData,
                                                 Socket targetSocket) {
        String clientIP = clientData.clientIP;
        try (InputStream targetInput = targetSocket.getInputStream();
             OutputStream targetOutput = targetSocket.getOutputStream()) {

            String path = "/"; 
            threadPool.execute(() -> forwardData(clientChannel, clientData, targetOutput)); 
            forwardData(targetInput, clientChannel, clientData);

            if (isDDoSAttack(clientIP, path)) {
                configManager.banIP(clientIP, TEMP_BAN_DURATION_MINUTES, TimeUnit.MINUTES);
                clientChannel.close(); 
                LOGGER.warning(String.format("DDoS attack detected from %s on path %s! " +
                                            "Connection temporarily blocked.",
                                             clientIP, path)); 
                logDDoSAttempt(clientIP); 
            }

        } catch (IOException e) { 
            LOGGER.log(Level.SEVERE, String.format("Error in DDoS protected connection: %s",
                                                   e.getMessage()), e);
            try {
                clientChannel.close();
            } catch (IOException ex) {
                LOGGER.log(Level.SEVERE, String.format("Error closing client channel: %s",
                        ex.getMessage()), ex); 
            }
        }
    } 

    private void logRequest(String clientIP, String rawRequest, Link link) {
        try {
            String[] requestLines = rawRequest.split("\r\n"); 
            String requestLine = requestLines[0]; 

            String[] requestParts = requestLine.split(" ");
            String method = requestParts[0];
            String path = requestParts.length > 1 ? requestParts[1] : ""; 

            Files.createDirectories(Paths.get(Main.LOGS_DIR));
            try (FileWriter writer = new FileWriter(Main.LOGS_DIR + "/access.log", true)) {
                DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"); 
                LocalDateTime now = LocalDateTime.now();
                writer.write(String.format("[%s] %s - %s %s %s - %s%n", 
                                             dtf.format(now), clientIP, link.getName(), 
                                            method, path,
                                            link.getTargetAddress()));
            }

        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, String.format("Failed to log request: %s", 
                                                      e.getMessage()), e); 
        }
    }

    private void forwardData(SocketChannel inputChannel, ClientData clientData,
                              OutputStream output) { 
        ByteBuffer buffer = ByteBuffer.allocate(8192);

        try {
            int bytesRead;
            while ((bytesRead = inputChannel.read(buffer)) > 0) {
                buffer.flip();
                byte[] data = new byte[bytesRead];
                buffer.get(data);
                output.write(data);
                output.flush();
                buffer.clear();
            } 
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, String.format("Error forwarding data from %s to target: %s",
                                                     clientData.clientIP, e.getMessage()), e); 
            try {
                inputChannel.close(); 
            } catch (IOException ex) { 
                LOGGER.log(Level.SEVERE, String.format("Error closing client channel: %s",
                                                      ex.getMessage()), ex);
            }
        } 
    } 

    private void forwardData(InputStream input, SocketChannel outputChannel, 
                            ClientData clientData) { 
        ByteBuffer buffer = ByteBuffer.allocate(8192); 
        byte[] data = new byte[8192];

        try { 
            int bytesRead;
            while ((bytesRead = input.read(data)) != -1) {
                buffer.put(data, 0, bytesRead);
                buffer.flip();
                outputChannel.write(buffer);
                buffer.compact(); 
            }
            buffer.flip(); 
            while (buffer.hasRemaining()) { 
                outputChannel.write(buffer);
            }

        } catch (IOException e) { 
            LOGGER.log(Level.WARNING, String.format("Error forwarding data to client %s: %s", 
                                                     clientData.clientIP, e.getMessage()), e);
            try {
                outputChannel.close();
            } catch (IOException ex) {
                LOGGER.log(Level.SEVERE, String.format("Error closing client channel: %s", 
                                                        ex.getMessage()), ex); 
            }
        }
    } 

    private String sanitizeRequest(String request, String clientIP) {
        request = processCsrfToken(request, clientIP);
        request = removeMaliciousHeaders(request);
        request = sanitizeCookies(request, clientIP);
        request = filterBlockedContent(request);
        return request; 
    }

    private String processCsrfToken(String request, String clientIP) {
        String[] lines = request.split("\r\n");
        StringBuilder newRequest = new StringBuilder();

        for (String line : lines) {
            if (line.toLowerCase().startsWith("csrf-token: ")) { 
                String token = line.substring("csrf-token: ".length()).trim();
                Link link = getLinkFromRequest(request); 
                if (link != null && link.isCsrfProtection() &&
                        !link.isValidCsrfToken(token)) { 
                    LOGGER.warning(String.format("Invalid CSRF token from %s on link %s",
                            clientIP, link.getName())); 
                    return null; 
                }
            } else { 
                newRequest.append(line).append("\r\n"); 
            } 
        }

        return newRequest.toString();
    }

    private Link getLinkFromRequest(String request) {
        String[] lines = request.split("\r\n"); 
        String hostHeader = Arrays.stream(lines) 
                .filter(line -> line.toLowerCase().startsWith("host: "))
                .findFirst() 
                .orElse(null);

        if (hostHeader != null) { 
            String host = hostHeader.substring("host: ".length()).trim();
            return links.values().stream()
                    .filter(l -> (l.getAssignedPort() == 80 && host.equals(l.getTargetAddress())) ||
                            (host.equals(l.getTargetAddress() + ":" + l.getAssignedPort())))
                    .findFirst() 
                    .orElse(null);
        }
        return null; 
    } 

    private String removeMaliciousHeaders(String request) { 
        List<String> blacklistedHeaders = Arrays.asList("referer", "user-agent", 
                                                      "x-forwarded-for", "x-forwarded-host");
        StringBuilder sanitizedRequest = new StringBuilder();
        String[] lines = request.split("\r\n"); 
        for (String line : lines) { 
            if (line.isEmpty()) {
                sanitizedRequest.append(line).append("\r\n"); 
                continue;
            }

            boolean headerIsBlacklisted = blacklistedHeaders.stream()
                    .anyMatch(h -> line.toLowerCase().startsWith(h + ":")); 
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
                            StringBuilder cookieBuilder = new StringBuilder(); 
                            cookieBuilder.append(name).append("=").append(value); 
                            if (configManager.isHttpOnly()) {
                                cookieBuilder.append("; HttpOnly");
                            } 
                            if (configManager.isSecureCookie()) {
                                cookieBuilder.append("; Secure");
                            } 
                            newCookies.add(cookieBuilder.toString());
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
        return name.matches("^[a-zA-Z0-9-_]+$");
    } 

    private boolean isValidTargetAddress(String address) {
        return address.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}:\\d+$");
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
            LOGGER.warning(String.format("Rate limiting triggered for IP: %s on path: %s. " + 
                                        "Request count: %d", ip, path, requestTimes.size()));
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
            LOGGER.log(Level.SEVERE, "Failed to log DDoS attempt: " +
                    e.getMessage(), e);
        }
    }

    private String encryptRequest(String request) throws Exception { 
        String key = configManager.getEncryptionKey(); 
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec); 

        byte[] iv = cipher.getIV(); 
        byte[] encrypted = cipher.doFinal(request.getBytes()); 
        return Base64.getEncoder().encodeToString(iv) + ":" +
                Base64.getEncoder().encodeToString(encrypted); 
    }

    private String decryptResponse(InputStream inputStream) throws Exception { 
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) { 
            String encryptedResponse = reader.readLine();
            if (encryptedResponse == null) { 
                return ""; 
            } 

            String[] parts = encryptedResponse.split(":");
            byte[] iv = Base64.getDecoder().decode(parts[0]); 
            byte[] encryptedBytes = Base64.getDecoder().decode(parts[1]); 

            String key = configManager.getEncryptionKey();
            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES"); 
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); 
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

            byte[] decrypted = cipher.doFinal(encryptedBytes);
            return new String(decrypted);
        }
    }

    private void sendResponseToClient(SocketChannel clientChannel, ClientData clientData, 
                                       String response) { 
        ByteBuffer buffer = ByteBuffer.wrap(response.getBytes()); 
        clientData.responseQueue.add(buffer); 

        SelectionKey key = clientChannel.keyFor(selector);
        key.interestOps(SelectionKey.OP_WRITE); 
        selector.wakeup(); 
    }

    private void stopProxyServer(Link link) { 
        LOGGER.info(String.format("Proxy server on port %d is being stopped.",
                                    link.getAssignedPort())); 
        try {
            for (SelectionKey key : selector.keys()) { 
                if (key.channel() instanceof ServerSocketChannel &&
                        ((ServerSocketChannel) key.channel()).socket().getLocalPort() == link.getAssignedPort()) {
                    key.cancel(); 
                    key.channel().close();
                    break; 
                } 
            } 
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, String.format("Error stopping proxy server on port %d: %s", 
                                                   link.getAssignedPort(), e.getMessage()), e);
        } 
    } 
} 

class Link {
    private final String targetAddress; 
    private final int assignedPort; 
    private boolean active; 
    private String mode; 
    private final String name; 
    private boolean csrfProtection;
    private String csrfToken; 

    public Link(String targetAddress, int assignedPort, String mode) { 
        this(targetAddress, assignedPort, mode, false, false, null);
    } 

    public Link(String targetAddress, int assignedPort, String mode, 
                boolean active, boolean csrfProtection, String csrfToken) { 
        this.targetAddress = targetAddress; 
        this.assignedPort = assignedPort;
        this.mode = mode;
        this.active = active; 
        this.name = generateLinkName(); 
        this.csrfProtection = csrfProtection;
        this.csrfToken = csrfToken;
        if (this.csrfProtection && this.csrfToken == null) {
            this.csrfToken = generateCsrfToken(); 
        } 
    } 

    public String getTargetAddress() {
        return targetAddress;
    }

    public int getAssignedPort() { 
        return assignedPort;
    }

    public String getMode() { 
        return mode; 
    } 

    public void setMode(String mode) {
        this.mode = mode; 
    }

    public boolean isActive() {
        return active; 
    }

    public void setActive(boolean active) {
        this.active = active; 
    } 

    public String getName() { 
        return name; 
    } 

    public boolean isCsrfProtection() { 
        return csrfProtection; 
    }

    public void setCsrfProtection(boolean csrfProtection) { 
        this.csrfProtection = csrfProtection; 
        if (csrfProtection && csrfToken == null) { 
            csrfToken = generateCsrfToken(); 
        }
    }

    public String getCsrfToken() {
        if (csrfToken == null) {
            csrfToken = generateCsrfToken(); 
        }
        return csrfToken;
    }

    private String generateCsrfToken() {
        return UUID.randomUUID().toString(); 
    } 

    public boolean isValidCsrfToken(String token) { 
        return token != null && token.equals(this.csrfToken);
    } 

    private String generateLinkName() { 
        return "link-" + UUID.randomUUID().toString().substring(0, 8);
    }
}

class ClientData {
    public Link link;
    public String clientIP;
    public Queue<ByteBuffer> responseQueue = new LinkedList<>(); 

    public ClientData(Link link, String clientIP) {
        this.link = link;
        this.clientIP = clientIP; 
    }
} 

class CommandHandler {
    private final LinkManager linkManager;
    private final ConfigManager configManager;
    private final NetworkManager networkManager;

    public CommandHandler(LinkManager linkManager, ConfigManager configManager,
                         NetworkManager networkManager) { 
        this.linkManager = linkManager;
        this.configManager = configManager; 
        this.networkManager = networkManager;
    } 

    public String handleCommand(String input) { 
        String[] parts = input.split(" "); 
        if (parts.length == 0) { 
            return "Invalid command.";
        } 
        String command = parts[0].toLowerCase();

        switch (command) {
            case "linkadd":
                if (parts.length == 5 &&
                        (parts[4].equals("forward") || 
                                parts[4].equals("ddosprot") || 
                                parts[4].equals("filterddosprot"))) { 
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
            case "blockcontent":
                if (parts.length > 1) {
                    String contentToBlock = String.join(" ", Arrays.copyOfRange(parts, 1, parts.length)); 
                    linkManager.blockContent(contentToBlock);
                    return "Content blocked: " + contentToBlock;
                } else {
                    return "Usage: blockcontent <content_to_block>"; 
                } 
            case "refreshconfig": 
                configManager.reloadConfig();
                if (configManager.isFleetModeEnabled() &&
                        !configManager.getMongoDbUrl().isEmpty()) {
                    networkManager.connectToMongoDB();
                    networkManager.registerInstance();
                } 
                return "Configuration refreshed.";
            case "networkinfo":
                if (configManager.isFleetModeEnabled()) {
                    networkManager.pingNetworkInstances();
                    return "Network information displayed in the logs."; 
                } else { 
                    return "Fleet Mode is disabled. Enable it in config.properties and restart the server.";
                } 
            default: 
                return """
                       Unknown command. Available commands:
                       - linkadd, linkremove, linkstart, linkstop, blockcontent 
                       - refreshconfig, networkinfo"""; 
        } 
    }
}