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

// Simple HTTP server implementation
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
        
        // Simple JSON parsing for FEN and depth
        std::string fen = extractJsonValue(body, "fen");
        std::string depth_str = extractJsonValue(body, "depth");
        int depth = depth_str.empty() ? 15 : std::stoi(depth_str);

        if (fen.empty()) {
            return "{\"error\": \"Missing FEN position\"}";
        }

        try {
            if (path == "/analyze") {
                std::string analysis = engine->analyze(fen, depth);
                return "{\"analysis\": \"" + escapeJson(analysis) + "\"}";
            } else if (path == "/bestmove") {
                std::string bestmove = engine->getBestMove(fen, depth);
                return "{\"bestmove\": \"" + bestmove + "\"}";
            } else {
                return "{\"error\": \"Unknown endpoint\"}";
            }
        } catch (const std::exception& e) {
            return "{\"error\": \"" + std::string(e.what()) + "\"}";
        }
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

        size_t value_start = json.find("\"", colon_pos);
        if (value_start == std::string::npos) {
            return "";
        }

        value_start++; // Skip opening quote
        size_t value_end = json.find("\"", value_start);
        if (value_end == std::string::npos) {
            return "";
        }

        return json.substr(value_start, value_end - value_start);
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
