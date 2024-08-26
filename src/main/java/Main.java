import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.*;

public class Main {
  private static final Logger LOGGER = Logger.getLogger(Main.class.getName());

  public static void main(String[] args) {
    setupLogger();
    LOGGER.info("Starting the application...");

    ConfigManager configManager = new ConfigManager();
    LinkManager linkManager = new LinkManager(configManager);
    CommandHandler commandHandler = new CommandHandler(linkManager);

    Scanner scanner = new Scanner(System.in);

    while (true) {
      System.out.print("Enter a command: ");
      String input = scanner.nextLine();
      String result = commandHandler.handleCommand(input);
      System.out.println(result);
    }
  }

  private static void setupLogger() {
    LogManager.getLogManager().reset();
    LOGGER.setLevel(Level.ALL);

    ConsoleHandler ch = new ConsoleHandler();
    ch.setLevel(Level.ALL);
    LOGGER.addHandler(ch);

    try {
      FileHandler fh = new FileHandler("application.log", true);
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
        bannedIPs = new HashSet<>(Arrays.asList(content.substring(1, content.length() - 1).split(", ")));
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
    return bannedIPs.contains(ip);
  }

  public void banIP(String ip) {
    bannedIPs.add(ip);
    saveBannedIPs();
    LOGGER.info("IP " + ip + " banned");
  }
}

class Config {
  private List<Integer> availablePorts;
  private boolean ddosProtectionEnabled;
  private int ddosTimeoutMinutes;

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
        .append("}");
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

    // Extract DDoS protection settings
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

  private Map<String, Long> recentRequests = new ConcurrentHashMap<>();

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

  public String addLink(String name, String targetAddress, String mode) {
    if (mode.equals("ddosprot") && !configManager.isDdosProtectionEnabled()) {
        return "Error: Cannot add link in 'ddosprot' mode. " +
               "DDoS protection is disabled in the configuration.";
    }
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
    LOGGER.info(
        "Link removed: " + name + ", Assigned Port " + link.getAssignedPort() + " returned to available ports.");
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
    // Stop the proxy server for this link
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
  }

  private void handleClient(Socket clientSocket, Link link) {
    String clientIP = ((InetSocketAddress) clientSocket.getRemoteSocketAddress()).getAddress().getHostAddress();

    LOGGER.info("Client connected: " + clientIP);

    if (configManager.isDdosProtectionEnabled() && isDDoSAttack(clientIP)) {
      LOGGER.warning("DDoS attack detected from " + clientIP + "! Connection dropped.");
      logDDoSAttempt(clientIP);
      configManager.banIP(clientIP);
      try {
        clientSocket.close();
      } catch (IOException e) {
        LOGGER.log(Level.WARNING, "Failed to close client socket", e);
      }
      return;
    }

    new Thread(() -> {
      String targetAddress = link.getTargetAddress();
      String[] addressParts = targetAddress.split(":");
      String targetHost = addressParts[0];
      int targetPort = Integer.parseInt(addressParts[1]);

      try (Socket targetSocket = new Socket(targetHost, targetPort)) {
        LOGGER.info(
            "Proxying connection from " + clientSocket.getRemoteSocketAddress() + " to " + targetHost + ":"
                + targetPort);

        InputStream clientInput = clientSocket.getInputStream();
        OutputStream clientOutput = clientSocket.getOutputStream();
        InputStream targetInput = targetSocket.getInputStream();
        OutputStream targetOutput = targetSocket.getOutputStream();

        // Forward data between client and target
        if (link.getMode().equals("forward")) {
          new Thread(() -> forwardData(clientInput, targetOutput)).start();
          forwardData(targetInput, clientOutput);
        } else if (link.getMode().equals("ddosprot")) {
          // Handle DDoS protection logic here
          // ...
        }
      } catch (IOException e) {
        LOGGER.log(Level.SEVERE, "Error in proxy connection to " + targetAddress, e);
      } finally {
        try {
          clientSocket.close();
        } catch (IOException e) {
          LOGGER.log(Level.WARNING, "Failed to close client socket", e);
        }
      }
    }).start();
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
      LOGGER.log(Level.WARNING, "Data forwarding error", e);
    }
  }

  private boolean isDDoSAttack(String ip) {
    long currentTime = System.currentTimeMillis();
    long requestCountThreshold = 10; // Adjust this value
    long timeWindowMillis = 5000; // 5 seconds

    recentRequests.putIfAbsent(ip, 0L);
    recentRequests.computeIfPresent(ip, (k, v) -> v + 1);

    if (recentRequests.get(ip) >= requestCountThreshold) {
      LOGGER.warning(
          "Potential DDoS attack detected from IP: " + ip + ". Request count exceeded threshold.");
      return true;
    }
    recentRequests.entrySet().removeIf(entry -> currentTime - entry.getValue() > timeWindowMillis);

    return false;
  }

  private void logDDoSAttempt(String ip) {
    try {
      Files.createDirectories(Paths.get("logs"));
      FileWriter writer = new FileWriter("logs/ddoslogs.txt", true);
      DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
      LocalDateTime now = LocalDateTime.now();
      writer.write("[" + dtf.format(now) + "] Potential DDoS attack detected from: " + ip + "\n");
      writer.close();
    } catch (IOException e) {
      LOGGER.log(Level.SEVERE, "Failed to log DDoS attempt", e);
    }
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
      if (parts.length == 4) { // Assuming mode is included
        String name = parts[0];
        String targetAddress = parts[1];
        int assignedPort = Integer.parseInt(parts[2]);
        String mode = parts[3]; // Get the mode
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
          .append(entry.getValue().getMode()).append("\"}"); // Include mode
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
        if (parts.length == 5 && (parts[4].equals("forward") || parts[4].equals("ddosprot"))) {
          return linkManager.addLink(parts[1], parts[2], parts[4]); // Pass the mode
        } else {
          return "Usage: linkadd <name> <targetAddress> <mode(forward/ddosprot)>";
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