import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DDoSProtectionServer {
    private static final String CONFIG_DIR = "config";
    private static final String CONFIG_FILE = "config.json";
    private static final String LOGS_DIR = "logs";
    private static final String LOGS_FILE = "logs.json";

    private static final Map<String, Integer> mainServerToPort = new ConcurrentHashMap<>();
    private static final Map<Integer, String> portToMainServer = new ConcurrentHashMap<>();
    private static final Map<String, Integer> availablePorts = new HashMap<>();
    private static final Map<String, Long> ipRequestCounts = new ConcurrentHashMap<>();
    private static final Map<String, Long> ipLastRequestTime = new ConcurrentHashMap<>();
    private static final Map<String, Boolean> ipBlacklist = new ConcurrentHashMap<>();
    private static final Map<String, Boolean> ipWhitelist = new ConcurrentHashMap<>();

    private static String discordWebhook;
    private static int ddosProtectionServerPort;
    private static String ddosProtectionServerIp;
    private static String ddosProtectionSystem;
    private static long requestRateLimit;
    private static long requestRatePeriod;
    private static int maxAvailablePorts;
    private static List<Integer> initialAvailablePorts;
    private static int blacklistThreshold;
    private static long blacklistDuration;
    private static boolean captchaEnabled;
    private static String captchaDifficulty;
    private static List<String> headersToAnalyze;
    private static String logFilePath;
    private static Level logLevel;
    private static int maxConcurrentConnections;
    private static int requestQueueSize;
    private static String cloudFlareApiKey;
    private static String cloudFlareEmail;

    private static final Logger logger = Logger.getLogger(DDoSProtectionServer.class.getName());

    public static void main(String[] args) {
        loadConfig();
        initializeAvailablePorts();
        startServer();
        logEvent("Server started");
    }

    private static void loadConfig() {
        File configDir = new File(CONFIG_DIR);
        File configFile = new File(configDir, CONFIG_FILE);

        if (!configDir.exists()) {
            configDir.mkdirs();
        }

        if (!configFile.exists()) {
            try {
                configFile.createNewFile();
                JsonObject config = new JsonObject();
                config.addProperty("ddosProtectionSystem", "rateLimit");
                config.addProperty("ddosProtectionServerPort", 8000);
                config.addProperty("ddosProtectionServerIp", "localhost");
                FileWriter writer = new FileWriter(configFile);
                writer.write(config.toString());
                writer.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        try {
            JsonObject config = JsonParser.parseReader(new FileReader(configFile)).getAsJsonObject();
            ddosProtectionServerPort = config.get("ddosProtectionServerPort").getAsInt();
            ddosProtectionServerIp = config.get("ddosProtectionServerIp").getAsString();
            ddosProtectionSystem = config.get("ddosProtectionSystem").getAsString();
            requestRateLimit = config.get("requestRateLimit").getAsLong();
            requestRatePeriod = config.get("requestRatePeriodMs").getAsLong();
            maxAvailablePorts = config.get("maxAvailablePorts").getAsInt();
            initialAvailablePorts = gson.fromJson(config.get("initialAvailablePorts"), new TypeToken<List<Integer>>() {}.getType());
            discordWebhook = config.get("discordWebhook").getAsString();
            ipWhitelist = gson.fromJson(config.get("whitelistedIps"), new TypeToken<Map<String, Boolean>>() {}.getType());
            blacklistThreshold = config.get("blacklistThreshold").getAsInt();
            blacklistDuration = config.get("blacklistDurationMs").getAsLong();
            captchaEnabled = config.get("captchaEnabled").getAsBoolean();
            captchaDifficulty = config.get("captchaDifficulty").getAsString();
            headersToAnalyze = gson.fromJson(config.get("headersToAnalyze"), new TypeToken<List<String>>() {}.getType());
            logFilePath = config.get("logFilePath").getAsString();
            logLevel = Level.parse(config.get("logLevel").getAsString());
            maxConcurrentConnections = config.get("maxConcurrentConnections").getAsInt();
            requestQueueSize = config.get("requestQueueSize").getAsInt();
            cloudFlareApiKey = config.get("cloudFlareApiKey").getAsString();
            cloudFlareEmail = config.get("cloudFlareEmail").getAsString();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void initializeAvailablePorts() {
        for (int port : initialAvailablePorts) {
            availablePorts.put(String.valueOf(port), port);
        }
    }

    private static void startServer() {
        HttpServer server;
        try {
            server = HttpServer.create(new InetSocketAddress(ddosProtectionServerIp, ddosProtectionServerPort), requestQueueSize);
            server.createContext("/api", new ApiHandler());
            server.setExecutor(null);
            server.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static class ApiHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String requestMethod = exchange.getRequestMethod();
            String requestPath = exchange.getRequestURI().getPath();
            String remoteAddress = exchange.getRemoteAddress().getAddress().getHostAddress();

            if (ipWhitelist.containsKey(remoteAddress)) {
                // Whitelisted IP, bypass DDoS protection
                handleRequest(exchange, requestMethod, requestPath, remoteAddress);
                return;
            }

            if (isDDoSAttack(remoteAddress)) {
                logDDoSAttempt(remoteAddress, exchange.getRequestHeaders(), DDoSLevel.HIGH);
                sendResponse(exchange, 429, "Too Many Requests");
                return;
            }

            handleRequest(exchange, requestMethod, requestPath, remoteAddress);
        }

        private void handleRequest(HttpExchange exchange, String requestMethod, String requestPath, String remoteAddress) throws IOException {
            if (requestMethod.equalsIgnoreCase("POST")) {
                String requestBody = new String(exchange.getRequestBody().readAllBytes());
                JsonObject requestJson = JsonParser.parseString(requestBody).getAsJsonObject();

                String command = requestJson.get("command").getAsString();
                String argument = requestJson.get("argument").getAsString();

                switch (command) {
                    case "setconnection":
                        setConnection(argument, remoteAddress);
                        break;
                    case "listports":
                        listPorts();
                        break;
                    case "connections":
                        connections();
                        break;
                    case "deleteconnection":
                        deleteConnection(argument);
                        break;
                    case "addiscordhook":
                        addDiscordWebhook(argument);
                        break;
                    case "addport":
                        addPort(argument);
                        break;
                    case "setddossystem":
                        setDDoSProtectionSystem(argument);
                        break;
                    default:
                        sendResponse(exchange, 400, "Invalid command");
                }
            } else {
                sendResponse(exchange, 405, "Method Not Allowed");
            }
        }
    }

    private static void sendResponse(HttpExchange exchange, int statusCode, String response) throws IOException {
        exchange.sendResponseHeaders(statusCode, response.getBytes().length);
        exchange.getResponseBody().write(response.getBytes());
        exchange.getResponseBody().close();
    }

    private static void setConnection(String mainServerIP, String remoteAddress) {
        if (availablePorts.isEmpty()) {
            logEvent("No available ports.");
            return;
        }

        int port = availablePorts.keySet().iterator().next();
        availablePorts.remove(String.valueOf(port));
        mainServerToPort.put(mainServerIP, port);
        portToMainServer.put(port, mainServerIP);

        logEvent("Connect to " + mainServerIP + " using " + ddosProtectionServerIp + ":" + port);
    }

    private static void listPorts() {
        logEvent("Available ports:");
        for (String port : availablePorts.keySet()) {
            logEvent(port);
        }

        logEvent("\nUsed ports:");
        for (Map.Entry<Integer, String> entry : portToMainServer.entrySet()) {
            logEvent(entry.getKey() + " -> " + entry.getValue());
        }
    }

    private static void connections() {
        for (Map.Entry<String, Integer> entry : mainServerToPort.entrySet()) {
            logEvent("Main Server IP: " + entry.getKey() + ", DDoS Protection Server IP:Port: " + ddosProtectionServerIp + ":" + entry.getValue());
        }
    }

    private static void deleteConnection(String mainServerIP) {
        if (mainServerToPort.containsKey(mainServerIP)) {
            int port = mainServerToPort.remove(mainServerIP);
            portToMainServer.remove(port);
            availablePorts.put(String.valueOf(port), port);
            logEvent("Connection to " + mainServerIP + " deleted.");
        } else {
            logEvent("No connection found for " + mainServerIP);
        }
    }

    private static void addDiscordWebhook(String webhookUrl) {
        discordWebhook = webhookUrl;
        logEvent("Discord webhook added: " + webhookUrl);
    }

    private static void addPort(String port) {
        if (availablePorts.containsKey(port)) {
            logEvent("Port " + port + " already exists in the available ports list.");
        } else {
            availablePorts.put(port, Integer.parseInt(port));
            logEvent("Port " + port + " added to the available ports list.");
        }
    }

    private static void setDDoSProtectionSystem(String system) {
        switch (system.toLowerCase()) {
            case "ratelimit":
            case "ipblacklist":
            case "cloudflare":
                ddosProtectionSystem = system;
                logEvent("DDoS protection system set to " + system);
                break;
            default:
                logEvent("Invalid DDoS protection system specified. Supported systems: rateLimit, ipBlacklist, cloudFlare");
        }
    }

    private static boolean isDDoSAttack(String remoteAddress) {
        switch (ddosProtectionSystem.toLowerCase()) {
            case "ratelimit":
                return isRateLimitDDoSAttack(remoteAddress);
            case "ipblacklist":
                return isIPBlacklistDDoSAttack(remoteAddress);
            case "cloudflare":
                // Implement CloudFlare DDoS protection logic here
                return false;
            default:
                return false;
        }
    }

    private static boolean isRateLimitDDoSAttack(String remoteAddress) {
        long currentTime = System.currentTimeMillis();
        ipRequestCounts.putIfAbsent(remoteAddress, 0L);
        ipLastRequestTime.putIfAbsent(remoteAddress, 0L);

        long lastRequestTime = ipLastRequestTime.get(remoteAddress);
        long requestCount = ipRequestCounts.get(remoteAddress);

        if (currentTime - lastRequestTime < requestRateLimit) {
            // Too many requests in a short period of time
            ipRequestCounts.put(remoteAddress, requestCount + 1);
            return true;
        } else if (currentTime - lastRequestTime > requestRatePeriod) {
            // Reset the request count if the period has elapsed
            ipRequestCounts.put(remoteAddress, 1L);
        } else {
            ipRequestCounts.put(remoteAddress, requestCount + 1);
            if (ipRequestCounts.get(remoteAddress) > MAX_REQUESTS_PER_PERIOD) {
                // Too many requests in the rate period
                return true;
            }
        }

        ipLastRequestTime.put(remoteAddress, currentTime);
        return false;
    }

    private static boolean isIPBlacklistDDoSAttack(String remoteAddress) {
        return ipBlacklist.containsKey(remoteAddress);
    }

    private static void logDDoSAttempt(String sourceIP, Map<String, List<String>> requestHeaders, DDoSLevel level) {
        File logsDir = new File(LOGS_DIR);
        File logsFile = new File(logsDir, LOGS_FILE);

        if (!logsDir.exists()) {
            logsDir.mkdirs();
        }

        if (!logsFile.exists()) {
            try {
                logsFile.createNewFile();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        try {
            JsonObject log = new JsonObject();
            log.addProperty("sourceIP", sourceIP);
            log.addProperty("level", level.toString());
            log.addProperty("timestamp", System.currentTimeMillis());

            JsonObject headers = new JsonObject();
            for (Map.Entry<String, List<String>> entry : requestHeaders.entrySet()) {
                JsonArray headerValues = new JsonArray();
                for (String value : entry.getValue()) {
                    headerValues.add(value);
                }
                headers.add(entry.getKey(), headerValues);
            }
            log.add("headers", headers);

            JsonParser parser = new JsonParser();
            JsonObject logFile = parser.parse(new FileReader(logsFile)).getAsJsonObject();
            logFile.add("logs", log);

            FileWriter writer = new FileWriter(logsFile);
            writer.write(logFile.toString());
            writer.close();

            logEvent("DDoS attempt from " + sourceIP + " with level " + level);
            if (discordWebhook != null) {
                logToDiscord("DDoS attempt from " + sourceIP + " with level " + level, discordWebhook);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void logEvent(String event) {
        logger.log(logLevel, event);
        if (discordWebhook != null) {
            logToDiscord(event, discordWebhook);
        }
    }

    private static void logToDiscord(String message, String webhookUrl) {
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(webhookUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"content\":\"" + message + "\"}"))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
                    if (response.statusCode() == 204) {
            logEvent("Message sent to Discord webhook successfully");
        } else {
            logEvent("Failed to send message to Discord webhook. Status code: " + response.statusCode());
        }
    } catch (IOException | InterruptedException e) {
        e.printStackTrace();
    }
}

private enum DDoSLevel {
    LOW, MEDIUM, HIGH
}
