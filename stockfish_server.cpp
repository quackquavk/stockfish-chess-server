#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <memory>
#include <chrono>
#include <regex>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <iomanip>

// Simple HTTP server implementation
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct PVLine {
    std::string bestmove;
    int score_cp = 0;        // Centipawn evaluation
    bool is_mate = false;    // Is this a mate score?
    int mate_in = 0;         // Mate in X moves (if is_mate is true)
    int depth = 0;
    std::vector<std::string> pv; // Principal variation moves
    std::string pv_string;   // PV as a single string
};

struct AnalysisResult {
    std::vector<PVLine> variations;
    std::string raw_output;
    int total_depth = 0;
    long long nodes = 0;
    int time_ms = 0;
};

class StockfishEngine {
private:
    int stdin_pipe[2];
    int stdout_pipe[2];
    pid_t child_pid;
    bool initialized;
    std::mutex engine_mutex;

public:
    StockfishEngine() : initialized(false), child_pid(-1) {}

    ~StockfishEngine() {
        if (initialized) {
            stop();
        }
    }

    bool start(const std::string& stockfish_path = "stockfish") {
        if (pipe(stdin_pipe) == -1 || pipe(stdout_pipe) == -1) {
            std::cerr << "Failed to create pipes" << std::endl;
            return false;
        }

        child_pid = fork();
        if (child_pid == -1) {
            std::cerr << "Failed to fork process" << std::endl;
            return false;
        }

        if (child_pid == 0) {
            // Child process - run Stockfish
            dup2(stdin_pipe[0], STDIN_FILENO);
            dup2(stdout_pipe[1], STDOUT_FILENO);
            
            close(stdin_pipe[0]);
            close(stdin_pipe[1]);
            close(stdout_pipe[0]);
            close(stdout_pipe[1]);

            execlp(stockfish_path.c_str(), stockfish_path.c_str(), nullptr);
            exit(1);
        }

        // Parent process
        close(stdin_pipe[0]);
        close(stdout_pipe[1]);
        
        initialized = true;
        
        // Initialize UCI
        sendCommand("uci");
        std::string response = readUntil("uciok");
        sendCommand("isready");
        readUntil("readyok");
        
        return true;
    }

    void stop() {
        if (initialized && child_pid != -1) {
            sendCommand("quit");
            kill(child_pid, SIGTERM);
            waitpid(child_pid, nullptr, 0);
            close(stdin_pipe[1]);
            close(stdout_pipe[0]);
            initialized = false;
        }
    }

    std::string analyze(const std::string& fen, int depth = 15, int time_ms = 1000) {
        std::lock_guard<std::mutex> lock(engine_mutex);
        
        if (!initialized) {
            return "ERROR: Engine not initialized";
        }

        // Set position
        sendCommand("position fen " + fen);
        sendCommand("isready");
        readUntil("readyok");

        // Start analysis
        std::string go_command = "go depth " + std::to_string(depth);
        if (time_ms > 0) {
            go_command += " movetime " + std::to_string(time_ms);
        }
        
        sendCommand(go_command);
        
        // Read analysis output
        std::string analysis_output;
        std::string line;
        
        while (true) {
            line = readLine();
            analysis_output += line + "\n";
            
            if (line.find("bestmove") == 0) {
                break;
            }
        }
        
        return analysis_output;
    }

    AnalysisResult analyzePV(const std::string& fen, int depth = 15, int multipv = 1, int time_ms = 1000) {
        std::lock_guard<std::mutex> lock(engine_mutex);
        
        AnalysisResult result;
        
        if (!initialized) {
            result.raw_output = "ERROR: Engine not initialized";
            return result;
        }

        // Set MultiPV option
        sendCommand("setoption name MultiPV value " + std::to_string(multipv));
        sendCommand("isready");
        readUntil("readyok");

        // Set position
        sendCommand("position fen " + fen);
        sendCommand("isready");
        readUntil("readyok");

        // Start analysis
        std::string go_command = "go depth " + std::to_string(depth);
        if (time_ms > 0) {
            go_command += " movetime " + std::to_string(time_ms);
        }
        
        sendCommand(go_command);
        
        // Read analysis output
        std::string analysis_output;
        std::string line;
        
        while (true) {
            line = readLine();
            analysis_output += line + "\n";
            
            if (line.find("bestmove") == 0) {
                break;
            }
        }
        
        result.raw_output = analysis_output;
        result = parseAnalysisOutput(analysis_output);
        
        return result;
    }

    std::string getBestMove(const std::string& fen, int depth = 15) {
        std::string analysis = analyze(fen, depth);
        
        // Extract best move from analysis
        std::regex bestmove_regex("bestmove\\s+(\\w+)");
        std::smatch match;
        
        if (std::regex_search(analysis, match, bestmove_regex)) {
            return match[1].str();
        }
        
        return "ERROR: No best move found";
    }

private:
    AnalysisResult parseAnalysisOutput(const std::string& output) {
        AnalysisResult result;
        std::istringstream iss(output);
        std::string line;
        
        // Store all PV lines by multipv number
        std::map<int, PVLine> pv_map;
        
        while (std::getline(iss, line)) {
            if (line.find("info depth") == 0) {
                PVLine pv_line = parseInfoLine(line);
                if (!pv_line.bestmove.empty()) {
                    // Find multipv number or default to 1
                    int multipv_num = 1;
                    std::regex multipv_regex("multipv (\\d+)");
                    std::smatch multipv_match;
                    if (std::regex_search(line, multipv_match, multipv_regex)) {
                        multipv_num = std::stoi(multipv_match[1].str());
                    }
                    pv_map[multipv_num] = pv_line;
                }
            } else if (line.find("bestmove") == 0) {
                // Extract overall stats from final info lines
                std::regex bestmove_regex("bestmove\\s+(\\w+)");
                std::smatch match;
                if (std::regex_search(line, match, bestmove_regex) && !pv_map.empty()) {
                    // Ensure the bestmove matches the first PV line
                    if (pv_map.find(1) != pv_map.end()) {
                        pv_map[1].bestmove = match[1].str();
                    }
                }
            }
        }
        
        // Convert map to vector, ordered by multipv number
        for (const auto& pair : pv_map) {
            result.variations.push_back(pair.second);
        }
        
        // Extract overall analysis stats
        extractOverallStats(output, result);
        
        return result;
    }
    
    PVLine parseInfoLine(const std::string& line) {
        PVLine pv_line;
        
        // Extract depth
        std::regex depth_regex("depth (\\d+)");
        std::smatch depth_match;
        if (std::regex_search(line, depth_match, depth_regex)) {
            pv_line.depth = std::stoi(depth_match[1].str());
        }
        
        // Extract score
        std::regex cp_regex("score cp (-?\\d+)");
        std::regex mate_regex("score mate (-?\\d+)");
        std::smatch score_match;
        
        if (std::regex_search(line, score_match, mate_regex)) {
            pv_line.is_mate = true;
            pv_line.mate_in = std::stoi(score_match[1].str());
        } else if (std::regex_search(line, score_match, cp_regex)) {
            pv_line.is_mate = false;
            pv_line.score_cp = std::stoi(score_match[1].str());
        }
        
        // Extract PV (principal variation)
        std::regex pv_regex("pv (.+)$");
        std::smatch pv_match;
        if (std::regex_search(line, pv_match, pv_regex)) {
            pv_line.pv_string = pv_match[1].str();
            
            // Split PV into individual moves
            std::istringstream pv_stream(pv_line.pv_string);
            std::string move;
            while (pv_stream >> move) {
                pv_line.pv.push_back(move);
            }
            
            // First move is the best move
            if (!pv_line.pv.empty()) {
                pv_line.bestmove = pv_line.pv[0];
            }
        }
        
        return pv_line;
    }
    
    void extractOverallStats(const std::string& output, AnalysisResult& result) {
        std::istringstream iss(output);
        std::string line;
        
        // Find the last info line with complete stats
        while (std::getline(iss, line)) {
            if (line.find("info depth") == 0) {
                // Extract nodes
                std::regex nodes_regex("nodes (\\d+)");
                std::smatch nodes_match;
                if (std::regex_search(line, nodes_match, nodes_regex)) {
                    result.nodes = std::stoll(nodes_match[1].str());
                }
                
                // Extract time
                std::regex time_regex("time (\\d+)");
                std::smatch time_match;
                if (std::regex_search(line, time_match, time_regex)) {
                    result.time_ms = std::stoi(time_match[1].str());
                }
                
                // Extract depth
                std::regex depth_regex("depth (\\d+)");
                std::smatch depth_match;
                if (std::regex_search(line, depth_match, depth_regex)) {
                    result.total_depth = std::stoi(depth_match[1].str());
                }
            }
        }
    }

    void sendCommand(const std::string& command) {
        std::string cmd = command + "\n";
        write(stdin_pipe[1], cmd.c_str(), cmd.length());
    }

    std::string readLine() {
        std::string line;
        char ch;
        
        while (read(stdout_pipe[0], &ch, 1) > 0) {
            if (ch == '\n') {
                break;
            }
            line += ch;
        }
        
        return line;
    }

    std::string readUntil(const std::string& expected) {
        std::string output;
        std::string line;
        
        while (true) {
            line = readLine();
            output += line + "\n";
            
            if (line.find(expected) != std::string::npos) {
                break;
            }
        }
        
        return output;
    }
};

class ChessAnalysisServer {
private:
    int server_socket;
    int port;
    std::unique_ptr<StockfishEngine> engine;
    bool running;

public:
    ChessAnalysisServer(int p = 8080) : port(p), running(false) {
        engine = std::make_unique<StockfishEngine>();
    }

    ~ChessAnalysisServer() {
        stop();
    }

    bool start() {
        // Initialize Stockfish engine
        if (!engine->start()) {
            std::cerr << "Failed to start Stockfish engine" << std::endl;
            return false;
        }

        // Create socket
        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket == -1) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }

        // Set socket options
        int opt = 1;
        setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        // Bind socket
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
            std::cerr << "Failed to bind socket" << std::endl;
            close(server_socket);
            return false;
        }

        // Listen for connections
        if (listen(server_socket, 10) == -1) {
            std::cerr << "Failed to listen on socket" << std::endl;
            close(server_socket);
            return false;
        }

        running = true;
        std::cout << "Chess Analysis Server started on port " << port << std::endl;
        std::cout << "Available endpoints:" << std::endl;
        std::cout << "  POST /analyze - Analyze position (JSON: {\"fen\": \"...\", \"depth\": 15})" << std::endl;
        std::cout << "  POST /bestmove - Get best move (JSON: {\"fen\": \"...\", \"depth\": 15})" << std::endl;
        std::cout << "  POST /pv - Get multiple variations (JSON: {\"fen\": \"...\", \"depth\": 15, \"multipv\": 3})" << std::endl;

        return true;
    }

    void run() {
        while (running) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
            if (client_socket == -1) {
                if (running) {
                    std::cerr << "Failed to accept connection" << std::endl;
                }
                continue;
            }

            // Handle client in separate thread
            std::thread client_thread(&ChessAnalysisServer::handleClient, this, client_socket);
            client_thread.detach();
        }
    }

    void stop() {
        running = false;
        if (server_socket != -1) {
            close(server_socket);
        }
    }

private:
    void handleClient(int client_socket) {
        char buffer[4096];
        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received <= 0) {
            close(client_socket);
            return;
        }

        buffer[bytes_received] = '\0';
        std::string request(buffer);

        // Parse HTTP request
        std::string response = processRequest(request);
        
        // Send HTTP response
        std::string http_response = "HTTP/1.1 200 OK\r\n";
        http_response += "Content-Type: application/json\r\n";
        http_response += "Access-Control-Allow-Origin: *\r\n";
        http_response += "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n";
        http_response += "Access-Control-Allow-Headers: Content-Type\r\n";
        http_response += "Content-Length: " + std::to_string(response.length()) + "\r\n";
        http_response += "\r\n";
        http_response += response;

        send(client_socket, http_response.c_str(), http_response.length(), 0);
        close(client_socket);
    }

    std::string processRequest(const std::string& request) {
        // Extract method and path
        std::istringstream iss(request);
        std::string method, path;
        iss >> method >> path;

        // Handle OPTIONS request (CORS preflight)
        if (method == "OPTIONS") {
            return "{}";
        }

        // Extract JSON body
        size_t body_start = request.find("\r\n\r\n");
        if (body_start == std::string::npos) {
            return "{\"error\": \"Invalid request format\"}";
        }

        std::string body = request.substr(body_start + 4);
        
        // Simple JSON parsing for FEN, depth, and multipv
        std::string fen = extractJsonValue(body, "fen");
        std::string depth_str = extractJsonValue(body, "depth");
        std::string multipv_str = extractJsonValue(body, "multipv");
        std::string time_str = extractJsonValue(body, "time");
        
        int depth = depth_str.empty() ? 15 : std::stoi(depth_str);
        int multipv = multipv_str.empty() ? 1 : std::stoi(multipv_str);
        int time_ms = time_str.empty() ? 1000 : std::stoi(time_str);
        
        // Clamp multipv between 1 and 10 for safety
        multipv = std::max(1, std::min(10, multipv));

        if (fen.empty()) {
            return "{\"error\": \"Missing FEN position\"}";
        }

        try {
            if (path == "/analyze") {
                std::string analysis = engine->analyze(fen, depth, time_ms);
                return "{\"analysis\": \"" + escapeJson(analysis) + "\"}";
            } else if (path == "/bestmove") {
                std::string bestmove = engine->getBestMove(fen, depth);
                return "{\"bestmove\": \"" + bestmove + "\"}";
            } else if (path == "/pv") {
                AnalysisResult result = engine->analyzePV(fen, depth, multipv, time_ms);
                return formatPVResponse(result);
            } else {
                return "{\"error\": \"Unknown endpoint\"}";
            }
        } catch (const std::exception& e) {
            return "{\"error\": \"" + std::string(e.what()) + "\"}";
        }
    }

    std::string formatPVResponse(const AnalysisResult& result) {
        std::ostringstream json;
        json << "{\n";
        json << "  \"bestmove\": \"" << (result.variations.empty() ? "" : result.variations[0].bestmove) << "\",\n";
        json << "  \"evaluation\": ";
        
        if (!result.variations.empty()) {
            const PVLine& first_line = result.variations[0];
            if (first_line.is_mate) {
                json << "{\"type\": \"mate\", \"value\": " << first_line.mate_in << "},\n";
            } else {
                json << "{\"type\": \"cp\", \"value\": " << first_line.score_cp << "},\n";
            }
        } else {
            json << "null,\n";
        }
        
        json << "  \"depth\": " << result.total_depth << ",\n";
        json << "  \"nodes\": " << result.nodes << ",\n";
        json << "  \"time\": " << result.time_ms << ",\n";
        json << "  \"variations\": [\n";
        
        for (size_t i = 0; i < result.variations.size(); ++i) {
            const PVLine& line = result.variations[i];
            json << "    {\n";
            json << "      \"move\": \"" << line.bestmove << "\",\n";
            json << "      \"evaluation\": ";
            
            if (line.is_mate) {
                json << "{\"type\": \"mate\", \"value\": " << line.mate_in << "},\n";
            } else {
                json << "{\"type\": \"cp\", \"value\": " << line.score_cp << "},\n";
            }
            
            json << "      \"depth\": " << line.depth << ",\n";
            json << "      \"pv\": [";
            
            for (size_t j = 0; j < line.pv.size(); ++j) {
                json << "\"" << line.pv[j] << "\"";
                if (j < line.pv.size() - 1) json << ", ";
            }
            
            json << "],\n";
            json << "      \"pv_string\": \"" << escapeJson(line.pv_string) << "\"\n";
            json << "    }";
            
            if (i < result.variations.size() - 1) json << ",";
            json << "\n";
        }
        
        json << "  ]\n";
        json << "}";
        
        return json.str();
    }

    std::string extractJsonValue(const std::string& json, const std::string& key) {
        std::string search_key = "\"" + key + "\"";
        size_t key_pos = json.find(search_key);
        
        if (key_pos == std::string::npos) {
            return "";
        }

        size_t colon_pos = json.find(":", key_pos);
        if (colon_pos == std::string::npos) {
            return "";
        }

        // Skip whitespace after colon
        size_t value_start = colon_pos + 1;
        while (value_start < json.length() && std::isspace(json[value_start])) {
            value_start++;
        }

        // Check if value is a string (starts with quote) or number
        if (value_start < json.length() && json[value_start] == '"') {
            // String value
            value_start++; // Skip opening quote
            size_t value_end = json.find("\"", value_start);
            if (value_end == std::string::npos) {
                return "";
            }
            return json.substr(value_start, value_end - value_start);
        } else {
            // Number value
            size_t value_end = value_start;
            while (value_end < json.length() && 
                   (std::isdigit(json[value_end]) || json[value_end] == '.' || json[value_end] == '-')) {
                value_end++;
            }
            return json.substr(value_start, value_end - value_start);
        }
    }

    std::string escapeJson(const std::string& str) {
        std::string result;
        for (char c : str) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c; break;
            }
        }
        return result;
    }
};

int main(int argc, char* argv[]) {
    int port = 8080;
    
    if (argc > 1) {
        port = std::atoi(argv[1]);
    }

    // Get port from environment if set
    const char* env_port = getenv("PORT");
    if (env_port != nullptr) {
        port = std::atoi(env_port);
    }

    ChessAnalysisServer server(port);
    
    if (!server.start()) {
        std::cerr << "Failed to start server" << std::endl;
        return 1;
    }

    // Handle Ctrl+C gracefully
    signal(SIGINT, [](int) {
        std::cout << "\nShutting down server..." << std::endl;
        exit(0);
    });

    server.run();
    
    return 0;
}